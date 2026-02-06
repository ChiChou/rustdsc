use crate::utils::print_hex_dump;
use object::read::macho::DyldCache;
use object::{LittleEndian, Object, ObjectSection, ObjectSymbol};
use std::error::Error;

pub fn cmd_images(cache: &DyldCache<LittleEndian>) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        println!("{}", image.path().unwrap_or(""));
    }
    Ok(())
}

pub fn cmd_sections(
    cache: &DyldCache<LittleEndian>,
    filter_module: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        let image_path = image.path().unwrap_or("");

        if let Some(filter) = filter_module
            && image_path != filter
        {
            continue;
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

pub fn cmd_symbols(
    cache: &DyldCache<LittleEndian>,
    filter_module: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    for image in cache.images() {
        let image_path = image.path().unwrap_or("");

        if let Some(filter) = filter_module
            && image_path != filter
        {
            continue;
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

pub fn cmd_dump(
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
