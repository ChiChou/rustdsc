use memmap2;
use object::LittleEndian;
use object::Object;
use object::ObjectSection;
use object::read::macho::DyldCache;
use std::error::Error;
use std::fs;

fn print_images(path: &str) -> Result<(), Box<dyn Error>> {
    let main_fd = fs::File::open(path)?;
    let main_mmap = unsafe { memmap2::Mmap::map(&main_fd)? };
    let suffixes = DyldCache::<LittleEndian>::subcache_suffixes(&*main_mmap)?;
    let mut subcache_mmaps = Vec::new();
    for suffix in &suffixes {
        let subcache_path = format!("{}{}", path, suffix);
        let subcache_fd = fs::File::open(&subcache_path)?;
        let subcache_mmap = unsafe { memmap2::Mmap::map(&subcache_fd)? };
        subcache_mmaps.push(subcache_mmap);
    }

    let subcache_data: Vec<&[u8]> = subcache_mmaps.iter().map(|m| &**m).collect();
    let cache = DyldCache::<LittleEndian>::parse(&*main_mmap, &subcache_data)?;
    for image in cache.images() {
        println!("{}", image.path().unwrap());
        let object = image.parse_object().unwrap();
        for section in object.sections() {
            let base = section.address();
            let end = base + section.size();
            println!(
                "  {:16} {:X}-{:X}",
                section.name().unwrap_or("N/A"),
                base,
                end
            );
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => return Err("usage: <program> <path>".into()),
    };

    print_images(&path)
}
