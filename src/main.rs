#![forbid(unsafe_code)]

use std::{
    fs::File,
    io,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use clap::Parser;
use hex::FromHexError;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rocksdb::{
    properties::ESTIMATE_NUM_KEYS, BlockBasedOptions, Cache, DBCompressionType, Options,
    SliceTransform, DB,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use thiserror::Error;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser)]
struct Opt {
    #[arg(long, default_value = "_db")]
    db: PathBuf,
    #[arg(long)]
    source: Vec<PathBuf>,
    #[arg(long)]
    compact: bool,
    #[arg(long)]
    bind: Option<SocketAddr>,
    #[arg(long, default_value = "268435456")]
    cache_bytes: usize,
}

struct Database {
    inner: DB,
}

impl Database {
    fn open(opt: &Opt) -> Result<Database, rocksdb::Error> {
        let cache = Cache::new_lru_cache(opt.cache_bytes)?;

        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&cache);
        table_opts.set_cache_index_and_filter_blocks(true);
        table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        table_opts.set_hybrid_ribbon_filter(10.0, 1);
        table_opts.set_whole_key_filtering(true);
        table_opts.set_format_version(5);

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        db_opts.set_block_based_table_factory(&table_opts);
        db_opts.set_compression_type(DBCompressionType::Lz4);
        db_opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        db_opts.set_level_compaction_dynamic_level_bytes(false);
        db_opts.set_prefix_extractor(SliceTransform::create_noop());

        let inner = DB::open(&db_opts, &opt.db)?;

        Ok(Database { inner })
    }

    fn set(&self, hash: PasswordHash, n: u64) -> Result<(), rocksdb::Error> {
        self.inner.put(hash.bytes, n.to_be_bytes())
    }

    fn get(&self, hash: PasswordHash) -> Result<u64, rocksdb::Error> {
        Ok(self
            .inner
            .get(hash.bytes)?
            .map_or(0, |bytes| bytes.try_into().map_or(0, u64::from_be_bytes)))
    }

    fn estimate_count(&self) -> Result<u64, rocksdb::Error> {
        Ok(self
            .inner
            .property_int_value(ESTIMATE_NUM_KEYS)?
            .unwrap_or(0))
    }

    fn compact(&self) -> () {
        self.inner.compact_range(None::<&[u8]>, None::<&[u8]>);
    }
}

#[derive(Debug, Error)]
#[error("Invalid password hash: {0}")]
struct InvalidPasswordHash(#[from] FromHexError);

struct PasswordHash {
    bytes: [u8; 20],
}

impl FromStr for PasswordHash {
    type Err = InvalidPasswordHash;

    fn from_str(s: &str) -> Result<PasswordHash, InvalidPasswordHash> {
        let mut bytes = [0; 20];
        hex::decode_to_slice(s, &mut bytes[..])?;
        Ok(PasswordHash { bytes })
    }
}

#[tokio::main]
async fn main() {
    let opt = Opt::parse();

    let db: &'static Database = Box::leak(Box::new(Database::open(&opt).expect("open database")));

    for source in opt.source {
        load(db, &source).expect("open source");
    }

    if opt.compact {
        log::info!("Compacting ...");
        db.compact();
    }

    if let Some(ref bind) = opt.bind {
        log::info!("Serving at {:?} ...", bind);

        let app = Router::new()
            .route("/status", get(status))
            .route("/", get(query))
            .with_state(db);

        axum::Server::bind(bind)
            .serve(app.into_make_service())
            .await
            .expect("bind");
    }
}

fn load(db: &Database, path: &Path) -> io::Result<()> {
    let file = File::open(path)?;

    let file = ProgressBar::with_draw_target(
        Some(file.metadata()?.len()),
        ProgressDrawTarget::stdout_with_hz(4),
    )
    .with_style(
        ProgressStyle::with_template(
            "{spinner} {prefix} {msg} {wide_bar} {bytes_per_sec:>14} {eta:>7}",
        )
        .unwrap(),
    )
    .with_prefix(format!("{path:?}"))
    .wrap_read(file);

    let uncompressed: Box<dyn io::Read> = if path.extension().map_or(false, |ext| ext == "zst") {
        log::info!("Loading compressed {:?} ...", path);
        Box::new(zstd::Decoder::new(file)?)
    } else {
        log::info!("Loading plain text {:?} ...", path);
        Box::new(file)
    };

    for line in BufReader::new(uncompressed).lines() {
        let line = line?;

        let (hash, n) = match line.split_once(':') {
            Some(parts) => parts,
            None => {
                log::warn!("Unexpected line format: {line}");
                continue;
            }
        };

        let hash = match hash.parse() {
            Ok(hash) => hash,
            Err(err) => {
                log::warn!("{err}: {line}");
                continue;
            }
        };
        let n = match n.parse() {
            Ok(n) => n,
            Err(err) => {
                log::warn!("{err}: {line}");
                continue;
            }
        };

        db.set(hash, n).expect("db set");
    }

    Ok(())
}

async fn status(State(db): State<&'static Database>) -> String {
    let count = db.estimate_count().expect("estimate count");
    format!("pwned count={count}u")
}

#[serde_as]
#[derive(Deserialize)]
struct Params {
    #[serde_as(as = "DisplayFromStr")]
    sha1: PasswordHash,
}

#[derive(Serialize)]
struct Response {
    n: u64,
}

async fn query(State(db): State<&'static Database>, Query(query): Query<Params>) -> Json<Response> {
    Json(Response {
        n: db.get(query.sha1).expect("db get"),
    })
}
