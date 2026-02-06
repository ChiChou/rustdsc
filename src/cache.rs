use memmap2::Mmap;
use object::LittleEndian;
use object::read::macho::DyldCache;
use std::error::Error;
use std::fs::File;

/// Owns the memory-mapped cache files so the parsed `DyldCache` can borrow from them.
pub struct MappedCache {
    main_mmap: Mmap,
    subcache_mmaps: Vec<Mmap>,
}

impl MappedCache {
    pub fn open(path: &str) -> Result<Self, Box<dyn Error>> {
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

        Ok(Self {
            main_mmap,
            subcache_mmaps,
        })
    }

    pub fn parse(&self) -> Result<DyldCache<'_, LittleEndian>, Box<dyn Error>> {
        let subcache_data: Vec<&[u8]> = self.subcache_mmaps.iter().map(|m| &**m).collect();
        let cache = DyldCache::<LittleEndian>::parse(&*self.main_mmap, &subcache_data)?;
        Ok(cache)
    }
}
