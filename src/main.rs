use clap::{Parser, Subcommand};
use std::error::Error;

mod cache;
mod extract;
mod inspect;
mod utils;

#[derive(Parser)]
#[command(name = "dsc")]
#[command(about = "A utility for inspecting Dyld Shared Cache")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Images {
        path: String,
    },
    Sections {
        path: String,
        #[arg(short, long)]
        module: Option<String>,
    },
    Symbols {
        path: String,
        #[arg(short, long)]
        module: Option<String>,
    },
    Dump {
        path: String,
        #[arg(value_parser = parse_u64)]
        addr: u64,
        #[arg(default_value_t = 256, value_parser = parse_u64)]
        size: u64,
    },
    Extract {
        path: String,
        dylib_path: String,
        output: Option<String>,
    },
}

fn parse_u64(input: &str) -> Result<u64, String> {
    let input = input.trim();
    if input.to_ascii_lowercase().starts_with("0x") {
        u64::from_str_radix(&input[2..], 16).map_err(|e| format!("Invalid hex: {}", e))
    } else {
        input
            .parse::<u64>()
            .map_err(|e| format!("Invalid number: {}", e))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let path = match &cli.command {
        Commands::Images { path }
        | Commands::Sections { path, .. }
        | Commands::Symbols { path, .. }
        | Commands::Dump { path, .. }
        | Commands::Extract { path, .. } => path.as_str(),
    };
    let mapped = cache::MappedCache::open(path)?;
    let cache = mapped.parse()?;

    match &cli.command {
        Commands::Images { .. } => inspect::cmd_images(&cache),
        Commands::Sections { module, .. } => inspect::cmd_sections(&cache, module.as_deref()),
        Commands::Symbols { module, .. } => inspect::cmd_symbols(&cache, module.as_deref()),
        Commands::Dump { addr, size, .. } => inspect::cmd_dump(&cache, *addr, *size as usize),
        Commands::Extract {
            dylib_path, output, ..
        } => extract::cmd_extract(&cache, dylib_path, output.as_deref()),
    }
}
