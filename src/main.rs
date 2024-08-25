#![forbid(unsafe_code)]

use std::{
    fs::File,
    io,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
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
use tokio::{net::TcpListener, time::sleep};

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
    upstream_update: bool,
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
        let cache = Cache::new_lru_cache(opt.cache_bytes);

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

    fn set(&self, hash: PasswordHash, n: u32) -> Result<(), rocksdb::Error> {
        self.inner.put(hash.bytes, n.to_be_bytes())
    }

    fn get(&self, hash: PasswordHash) -> Result<u32, rocksdb::Error> {
        Ok(self
            .inner
            .get(hash.bytes)?
            .map_or(0, |bytes| bytes.try_into().map_or(0, u32::from_be_bytes)))
    }

    fn estimate_count(&self) -> Result<u64, rocksdb::Error> {
        Ok(self
            .inner
            .property_int_value(ESTIMATE_NUM_KEYS)?
            .unwrap_or(0))
    }

    fn compact(&self) {
        self.inner.compact_range(None::<&[u8]>, None::<&[u8]>);
    }
}

#[derive(Debug, Error)]
#[error("Invalid password hash: {0}")]
struct InvalidPasswordHash(#[from] FromHexError);

#[derive(Debug, Eq, PartialEq)]
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

#[derive(Copy, Clone, Debug)]
struct PasswordHashPrefix(u32);

impl PasswordHashPrefix {
    const MAX: PasswordHashPrefix = PasswordHashPrefix(0xfffff);

    fn to_hex_string(&self) -> String {
        let s = hex::encode_upper(self.0.to_be_bytes());
        s[3..].to_string()
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let opt = Opt::parse();

    let db: &'static Database = Box::leak(Box::new(Database::open(&opt).expect("open database")));

    for source in opt.source {
        load(db, &source).expect("open source");
    }

    if opt.compact {
        log::info!("Compacting ...");
        db.compact();
    }

    if opt.upstream_update {
        tokio::spawn(upstream_update_forever(db));
    }

    if let Some(ref bind) = opt.bind {
        log::info!("Serving at {:?} ...", bind);

        let app = Router::new()
            .route("/status", get(status))
            .route("/", get(query))
            .with_state(db);

        let listener = TcpListener::bind(bind).await.expect("bind");
        axum::serve(listener, app).await.expect("serve");
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

        db.set(hash, n).expect("db set for load");
    }

    Ok(())
}

#[derive(Debug, Error)]
#[error("upstream error: {0}")]
enum UpstreamError {
    #[error("unexpected line: {0:?}")]
    UnexpectedLine(String),
    ReqwestError(#[from] reqwest::Error),
}

fn parse_upstream_range(
    prefix: PasswordHashPrefix,
    body: &str,
) -> Result<Vec<(PasswordHash, u32)>, UpstreamError> {
    let mut out = Vec::with_capacity(body.len() / 35);
    for line in body.lines() {
        let (suffix, n) = line
            .split_once(':')
            .ok_or(UpstreamError::UnexpectedLine(line.to_owned()))?;

        let mut hex_hash = prefix.to_hex_string();
        hex_hash.push_str(suffix);

        let hash = hex_hash
            .parse()
            .map_err(|_| UpstreamError::UnexpectedLine(line.to_owned()))?;
        let n = n
            .parse()
            .map_err(|_| UpstreamError::UnexpectedLine(line.to_owned()))?;
        out.push((hash, n));
    }
    Ok(out)
}

async fn upstream_update_range(
    db: &Database,
    client: &reqwest::Client,
    prefix: PasswordHashPrefix,
) -> Result<(), UpstreamError> {
    let body = client
        .get(format!(
            "https://api.pwnedpasswords.com/range/{}",
            prefix.to_hex_string()
        ))
        .send()
        .await?
        .text()
        .await?;

    let out = parse_upstream_range(prefix, &body)?;
    log::debug!(
        "Upstream update: Received {} records for prefix {}",
        out.len(),
        prefix.to_hex_string()
    );

    for (hash, n) in parse_upstream_range(prefix, &body)? {
        if n > 0 {
            db.set(hash, n).expect("db set for upstream update");
        }
    }

    Ok(())
}

async fn upstream_update_forever(db: &Database) {
    let client = reqwest::Client::builder()
        .user_agent("lila-pwned")
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    loop {
        log::info!("Beginning new upstream update ...");

        for prefix in 0..=PasswordHashPrefix::MAX.0 {
            let prefix = PasswordHashPrefix(prefix);

            if prefix.0 % 1800 == 0 {
                log::info!(
                    "Upstream update: At prefix {} (currently {} local records estimated)",
                    prefix.to_hex_string(),
                    db.estimate_count().expect("estimate count")
                );
            }

            if let Err(err) = upstream_update_range(db, &client, prefix).await {
                log::error!("{} at {}", err, prefix.to_hex_string());
            }

            sleep(Duration::from_secs(2)).await;
        }
    }
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
    n: u32,
}

async fn query(State(db): State<&'static Database>, Query(query): Query<Params>) -> Json<Response> {
    Json(Response {
        n: db.get(query.sha1).expect("db get"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_prefix() {
        assert_eq!(PasswordHashPrefix(0).to_hex_string(), "00000");
        assert_eq!(PasswordHashPrefix(1).to_hex_string(), "00001");
        assert_eq!(PasswordHashPrefix(0xab).to_hex_string(), "000AB");
        assert_eq!(PasswordHashPrefix(0xabc).to_hex_string(), "00ABC");
        assert_eq!(PasswordHashPrefix(0xabcd).to_hex_string(), "0ABCD");
        assert_eq!(PasswordHashPrefix(0xabcde).to_hex_string(), "ABCDE");
        assert_eq!(PasswordHashPrefix::MAX.to_hex_string(), "FFFFF");
    }

    #[test]
    fn test_parse_upstream_range() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
011053FD0102E94D6AE2F8B83D76FAF94F6:1
012A7CA357541F0AC487871FEEC1891C49C:2
0136E006E24E7D152139815FB0FC6A50B15:2";

        let out =
            parse_upstream_range(PasswordHashPrefix(0xabcde), body).expect("parse upstream range");

        assert_eq!(out.len(), 5);
        assert_eq!(
            out[0],
            (
                PasswordHash {
                    bytes: [
                        0xab, 0xcd, 0xe0, 0x01, 0x8A, 0x45, 0xC4, 0xD1, 0xDE, 0xF8, 0x16, 0x44,
                        0xB5, 0x4A, 0xB7, 0xF9, 0x69, 0xB8, 0x8D, 0x65
                    ]
                },
                1
            )
        );
    }
}
