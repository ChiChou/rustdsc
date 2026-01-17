use clap::{Parser, Subcommand};
use memmap2::Mmap;
use object::read::macho::DyldCache;
use object::{LittleEndian, Object, ObjectSection, ObjectSymbol};
use std::error::Error;
use std::fs::File;

mod utils;
use utils::print_hex_dump;

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

fn with_dyld_cache<F>(path: &str, action: F) -> Result<(), Box<dyn Error>>
where
    F: FnOnce(&DyldCache<LittleEndian>) -> Result<(), Box<dyn Error>>,
{
    let main_file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path, e))?;
    let main_mmap = unsafe { Mmap::map(&main_file)? };
    let suffixes = DyldCache::<LittleEndian>::subcache_suffixes(&*main_mmap)?;

    let mut subcache_mmaps = Vec::new();
    for suffix in suffixes {
        let sub_path = format!("{}{}", path, suffix);
        let sub_file = File::open(&sub_path)?;
        let sub_mmap = unsafe { Mmap::map(&sub_file)? };
        subcache_mmaps.push(sub_mmap);
    }

    let subcache_data: Vec<&[u8]> = subcache_mmaps.iter().map(|m| &**m).collect();
    let cache = DyldCache::<LittleEndian>::parse(&*main_mmap, &subcache_data)?;

    action(&cache)
}

fn cmd_images(cache: &DyldCache<LittleEndian>) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        println!("{}", image.path().unwrap_or(""));
    }
    Ok(())
}

fn cmd_sections(
    cache: &DyldCache<LittleEndian>,
    filter_module: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        let image_path = image.path().unwrap_or("");

        if let Some(filter) = filter_module {
            if image_path != filter {
                continue;
            }
        }

        println!("{}", image_path);
        if let Ok(obj) = image.parse_object() {
            for section in obj.sections() {
                let base = section.address();
                let end = base + section.size();
                println!(
                    "  {:16} 0x{:X}-0x{:X}",
                    section.name().unwrap_or(""),
                    base,
                    end
                );
            }
        }
    }
    Ok(())
}

fn cmd_symbols(
    cache: &DyldCache<LittleEndian>,
    filter_module: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        let image_path = image.path().unwrap_or("");

        if let Some(filter) = filter_module {
            if image_path != filter {
                continue;
            }
        }

        println!("{}", image_path);
        if let Ok(obj) = image.parse_object() {
            for symbol in obj.symbols() {
                println!("0x{:X} {}", symbol.address(), symbol.name().unwrap_or(""))
            }
        }
    }
    Ok(())
}

fn cmd_dump(
    cache: &DyldCache<LittleEndian>,
    vmaddr: u64,
    size: usize,
) -> Result<(), Box<dyn Error>> {
    match cache.data_and_offset_for_address(vmaddr) {
        Some((data, offset)) => {
            let off = offset as usize;
            if off >= data.len() {
                return Err(format!(
                    "Calculated offset {} is out of range (data len {})",
                    off,
                    data.len()
                )
                .into());
            }

            let end = std::cmp::min(data.len(), off + size);
            let bytes = &data[off..end];

            eprintln!("Mapped to file offset 0x{:X}", off);
            eprintln!(
                "Found VM address 0x{:X}, {} bytes available",
                vmaddr,
                bytes.len()
            );
            print_hex_dump(vmaddr, bytes);
            Ok(())
        }
        None => Err(format!("Address 0x{:X} not found in dyld cache", vmaddr).into()),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Images { path } => with_dyld_cache(path, |cache| cmd_images(cache)),
        Commands::Sections { path, module } => {
            with_dyld_cache(path, |cache| cmd_sections(cache, module.as_deref()))
        }
        Commands::Dump { path, addr, size } => {
            with_dyld_cache(path, |cache| cmd_dump(cache, *addr, *size as usize))
        }
        Commands::Symbols { path, module } => {
            with_dyld_cache(path, |cache| cmd_symbols(cache, module.as_deref()))
        }
    }
}
