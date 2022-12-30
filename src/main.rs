
use std::{str::FromStr, fs::File, io::Write};

use clap::Parser;
use ed25519_dalek::Sha512;
use encdec::{Encode, EncodeExt, Decode};
use log::{debug, info, LevelFilter};
use rand_core::OsRng;

use fwsig::{
    MetadataFormat, ManifestError,
    keys::{PrivateKey, PublicKey}, ManifestBuilder, MANIFEST_LEN, Manifest,
};
use simplelog::SimpleLogger;

/// fwsig firmware signing / packaging / verification utility
#[derive(Clone, PartialEq, Debug, Parser)]
struct Args {

    #[clap(subcommand)]
    ops: Ops,

    /// Log level
    #[clap(long, default_value = "info")]
    log_level: LevelFilter,
}

/// firmware signing / packaging / verification operations
#[derive(Clone, PartialEq, Debug, Parser)]
enum Ops {

    /// Sign an application binary and metadata, generating a manifest
    Sign{
        /// Application file
        app: String,

        /// Metadata file
        meta: String,
        
        /// Metadata format
        #[clap(long, default_value = "bin")]
        meta_format: MetadataFormat,

        /// Signing key, if not provided a transient per-operation key will be used
        #[clap(value_parser = parse_private_key)]
        key: Option<PrivateKey>,

        /// Output file
        #[clap(long)]
        output: String,

        /// Specify only manifest should be written to output file (detached mode)
        #[clap(long)]
        detached: bool,
    },

    /// Verify a signed application object (binary + metadata + manifest)
    VerifyAttached{
        /// Combined application file
        app: String,

        /// Allowed keys
        #[clap(value_parser = parse_public_key)]
        keys: Vec<PublicKey>,
    },

    /// Verify application components against a signed manifest
    VerifyDetached {
        /// Manifest file
        manifest: String,
        
        /// Application file
        app: String,

        /// Metadata file
        meta: String,

        /// Allowed signing keys
        #[clap(value_parser = parse_public_key)]
        keys: Vec<PublicKey>,
    }

}


fn parse_private_key(v: &str) -> Result<PrivateKey, ManifestError> {
    PrivateKey::from_str(v)
}


fn parse_public_key(v: &str) -> Result<PublicKey, ManifestError> {
    PublicKey::from_str(v)
}

fn main() -> anyhow::Result<()> {
    // Parse arguments
    let args = Args::parse();

    // Setup logging
    let _ = SimpleLogger::init(args.log_level, simplelog::Config::default());

    // Execute operations
    match args.ops {
        Ops::Sign { app, meta, meta_format, key, output, detached } => {
            info!("Signing manifest for app: {}", app);

            // Load app and meta files
            let app = std::fs::read(app)?;
            let meta = std::fs::read(meta)?;

            // Build manifest
            let m = ManifestBuilder::new()
                .app_bin(&app)
                .meta_bin(meta_format, &meta)
                .build::<OsRng>(key.map(|k| k.inner() ))?;
            
            // TODO: pretty manifest display
            info!("Generated manifest: {:?}", m);

            // Encode manifest data
            debug!("Encoding manifest");
            let (b, n) = m.encode_buff::<MANIFEST_LEN>()
                .map_err(|_e| anyhow::anyhow!("Encoding error"))?;

            // Write output file
            let mut f = File::create(output)?;
            if detached {
                // Detached mode, write manifest to output
                f.write_all(&b[..n])?;
            } else {
                // Combined mode, write app + meta + manifest to output
                f.write_all(&app)?;
                f.write_all(&meta)?;
                f.write_all(&b[..n])?;
            }

            f.flush()?;
            drop(f);
        },
        Ops::VerifyAttached { app, keys } => {
            // Read comined app file
            let data = std::fs::read(app)?;

            // Parse manifest
            let b = &data[data.len() - MANIFEST_LEN..];
            let (m, _) = Manifest::decode(&b).unwrap();

            // TODO: pretty manifest display
            info!("Parsed manifest: {:?}", m);

            // Check app components
            if data.len() != m.app_len() + m.meta_len() + MANIFEST_LEN {
                todo!("application length mismatch")
            }

            let app = &data[..m.app_len as usize];
            let app_csum = Manifest::checksum(app);

            if app_csum != m.app_csum {
                todo!("application checksum mismatch")
            }

            let meta = &data[m.app_len()..][..m.meta_len()];
            let meta_csum = Manifest::checksum(meta);

            if meta_csum != m.meta_csum {
                todo!("metadata checksum mismatch")
            }

            // Check signature
            let allowed_keys: Vec<_> = keys.iter().map(|k| k.clone().inner() ).collect();
            if let Err(e) = m.verify(&allowed_keys) {
                todo!("invalid app signature")
            }

            info!("App signature OK!");
        },
        Ops::VerifyDetached { manifest, app, meta, keys } => {
            todo!()
        },
    }

    Ok(())
}
