use memmap2::Mmap;
use object::read::macho::DyldCache;
use object::{LittleEndian, Object, ObjectSection};
use std::error::Error;
use std::fs::File;

fn with_dyld_cache<F>(path: &str, action: F) -> Result<(), Box<dyn Error>>
where
    F: FnOnce(&DyldCache<LittleEndian>) -> Result<(), Box<dyn Error>>,
{
    let main_file = File::open(path)?;
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

fn print_hex_dump(start_addr: u64, data: &[u8]) {
    println!(
        "Found VM address 0x{:X}, {} bytes available",
        start_addr,
        data.len()
    );

    for (row_idx, row) in data.chunks(16).enumerate() {
        let addr = start_addr + (row_idx * 16) as u64;
        print!("{:016X}: ", addr);
        for b in row {
            print!("{:02X} ", b);
        }

        if row.len() < 16 {
            for _ in 0..(16 - row.len()) {
                print!("   ");
            }
        }

        print!(" |");

        for b in row {
            let ch = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            print!("{}", ch);
        }
        println!("|");
    }
}

fn parse_u64(input: &str) -> Result<u64, String> {
    let input = input.trim();
    if input.to_ascii_lowercase().starts_with("0x") {
        u64::from_str_radix(&input[2..], 16).map_err(|e| e.to_string())
    } else {
        input.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn cmd_images(cache: &DyldCache<LittleEndian>) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        println!("{}", image.path().unwrap_or("N/A"));
    }
    Ok(())
}

fn cmd_sections(cache: &DyldCache<LittleEndian>) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        println!("{}", image.path().unwrap());
        let obj = image.parse_object().unwrap();
        for section in obj.sections() {
            let base = section.address();
            let end = base + section.size();
            println!(
                "  {:16} 0x{:X}-0x{:X}",
                section.name().unwrap_or("N/A"),
                base,
                end
            );
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

            println!("Mapped to file offset 0x{:X}", off);
            print_hex_dump(vmaddr, bytes);
            Ok(())
        }
        None => Err(format!("Address 0x{:X} not found in dyld cache", vmaddr).into()),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  dsc images <path>");
        eprintln!("  dsc dump   <path> <addr> [size]");
        return Ok(());
    }

    let command = args[1].as_str();
    let path = args.get(2).ok_or("Missing file path")?;

    with_dyld_cache(path, |cache| {
        match command {
            "images" => cmd_images(cache),
            "sections" => cmd_sections(cache),
            "dump" => {
                let addr_str = args.get(3).ok_or("Missing address for dump")?;
                let vmaddr = parse_u64(addr_str).map_err(|e| format!("Invalid address: {}", e))?;

                let size = if let Some(size_str) = args.get(4) {
                    parse_u64(size_str).map_err(|e| format!("Invalid size: {}", e))? as usize
                } else {
                    256 // default size
                };

                cmd_dump(cache, vmaddr, size)
            }
            _ => Err(format!("Unknown command: {}", command).into()),
        }
    })
}
