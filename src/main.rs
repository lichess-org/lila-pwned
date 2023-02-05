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
use rocksdb::{BlockBasedOptions, DBCompressionType, Options, SliceTransform, DB};
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
    bind: Option<SocketAddr>,
}

struct Database {
    inner: DB,
}

impl Database {
    fn open(path: impl AsRef<Path>) -> Result<Database, rocksdb::Error> {
        let mut table_opts = BlockBasedOptions::default();
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

        let inner = DB::open(&db_opts, path)?;

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

    let db: &'static Database = Box::leak(Box::new(Database::open(opt.db).expect("open database")));

    for source in opt.source {
        log::info!("Loading {:?} ...", source);
        load(db, source).expect("open source");
    }

    if let Some(ref bind) = opt.bind {
        log::info!("Serving at {:?} ...", bind);

        let app = Router::new().route("/", get(query)).with_state(db);

        axum::Server::bind(bind)
            .serve(app.into_make_service())
            .await
            .expect("bind");
    }
}

fn load(db: &Database, path: impl AsRef<Path>) -> io::Result<()> {
    for line in BufReader::new(File::open(path)?).lines() {
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
