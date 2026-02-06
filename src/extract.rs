use object::LittleEndian;
use object::macho;
use object::pod;
use object::read::macho::DyldCache;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::mem;
use std::path::Path;

const LE: LittleEndian = LittleEndian;

const PAGE_SIZE: u64 = 0x4000;

fn align_to(offset: u64, alignment: u64) -> u64 {
    (offset + alignment - 1) & !(alignment - 1)
}

/// Info about one LC_SEGMENT_64 collected during the read pass.
struct SegmentInfo {
    name: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    old_fileoff: u64,
    old_filesize: u64,
    /// Byte offset of this segment command within the header+loadcmds buffer.
    cmd_offset: usize,
}

fn seg_name(raw: &[u8; 16]) -> &str {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&raw[..end]).unwrap_or("")
}

/// Record a LINKEDIT (offset, end) bound if offset and byte size are both non-zero.
fn push_bound(bounds: &mut Vec<(u32, u32)>, off: u32, byte_size: u32) {
    if off != 0 && byte_size != 0 {
        bounds.push((off, off + byte_size));
    }
}

/// Patch a LINKEDIT offset field in-place: rebase if the associated size/count
/// is non-zero, otherwise zero out the stale cache offset.
macro_rules! patch_linkedit {
    ($cmd:expr, $off:ident, $size:ident, $new_base:expr, $min_off:expr) => {{
        let old = $cmd.$off.get(LE);
        if old != 0 && $cmd.$size.get(LE) != 0 {
            $cmd.$off.set(LE, $new_base + (old - $min_off));
        } else if old != 0 {
            $cmd.$off.set(LE, 0);
        }
    }};
}

pub fn cmd_extract(
    cache: &DyldCache<'_, LittleEndian>,
    dylib_path: &str,
    output: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    // --- Phase 1: Find image and read raw header ---
    let image = cache
        .images()
        .find(|img| img.path().ok() == Some(dylib_path))
        .ok_or_else(|| format!("Image '{}' not found in cache", dylib_path))?;

    let (header_data, header_offset) = image.image_data_and_offset()?;
    let header_bytes = &header_data[header_offset as usize..];

    let hdr_size = mem::size_of::<macho::MachHeader64<LittleEndian>>();
    let (header, _) = pod::from_bytes::<macho::MachHeader64<LittleEndian>>(header_bytes)
        .map_err(|_| "Failed to parse Mach-O header")?;
    let ncmds = header.ncmds.get(LE) as usize;
    let sizeofcmds = header.sizeofcmds.get(LE) as usize;

    // Copy header + load commands into mutable buffer
    let mut buf = header_bytes[..hdr_size + sizeofcmds].to_vec();

    // --- Phase 2: Collect segment info and LINKEDIT bounds ---
    let mut segments: Vec<SegmentInfo> = Vec::new();
    let mut linkedit_bounds: Vec<(u32, u32)> = Vec::new();

    let seg_cmd_size = mem::size_of::<macho::SegmentCommand64<LittleEndian>>();
    let sect_size = mem::size_of::<macho::Section64<LittleEndian>>();

    let mut cmd_pos = hdr_size;
    for _ in 0..ncmds {
        let (lc, _) = pod::from_bytes::<macho::LoadCommand<LittleEndian>>(&buf[cmd_pos..])
            .map_err(|_| "Failed to parse load command")?;
        let cmd = lc.cmd.get(LE);
        let cmdsize = lc.cmdsize.get(LE) as usize;

        match cmd {
            macho::LC_SEGMENT_64 => {
                let (seg, _) =
                    pod::from_bytes::<macho::SegmentCommand64<LittleEndian>>(&buf[cmd_pos..])
                        .unwrap();
                segments.push(SegmentInfo {
                    name: seg.segname,
                    vmaddr: seg.vmaddr.get(LE),
                    vmsize: seg.vmsize.get(LE),
                    old_fileoff: seg.fileoff.get(LE),
                    old_filesize: seg.filesize.get(LE),
                    cmd_offset: cmd_pos,
                });
            }
            macho::LC_SYMTAB => {
                let (c, _) =
                    pod::from_bytes::<macho::SymtabCommand<LittleEndian>>(&buf[cmd_pos..]).unwrap();
                push_bound(
                    &mut linkedit_bounds,
                    c.symoff.get(LE),
                    c.nsyms.get(LE) * 16, // nlist_64 is 16 bytes
                );
                push_bound(&mut linkedit_bounds, c.stroff.get(LE), c.strsize.get(LE));
            }
            macho::LC_DYSYMTAB => {
                let (c, _) =
                    pod::from_bytes::<macho::DysymtabCommand<LittleEndian>>(&buf[cmd_pos..])
                        .unwrap();
                push_bound(&mut linkedit_bounds, c.tocoff.get(LE), c.ntoc.get(LE) * 8);
                push_bound(
                    &mut linkedit_bounds,
                    c.modtaboff.get(LE),
                    c.nmodtab.get(LE) * 56,
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.extrefsymoff.get(LE),
                    c.nextrefsyms.get(LE) * 4,
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.indirectsymoff.get(LE),
                    c.nindirectsyms.get(LE) * 4,
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.extreloff.get(LE),
                    c.nextrel.get(LE) * 8,
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.locreloff.get(LE),
                    c.nlocrel.get(LE) * 8,
                );
            }
            macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY => {
                let (c, _) =
                    pod::from_bytes::<macho::DyldInfoCommand<LittleEndian>>(&buf[cmd_pos..])
                        .unwrap();
                push_bound(
                    &mut linkedit_bounds,
                    c.rebase_off.get(LE),
                    c.rebase_size.get(LE),
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.bind_off.get(LE),
                    c.bind_size.get(LE),
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.weak_bind_off.get(LE),
                    c.weak_bind_size.get(LE),
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.lazy_bind_off.get(LE),
                    c.lazy_bind_size.get(LE),
                );
                push_bound(
                    &mut linkedit_bounds,
                    c.export_off.get(LE),
                    c.export_size.get(LE),
                );
            }
            macho::LC_FUNCTION_STARTS
            | macho::LC_DATA_IN_CODE
            | macho::LC_CODE_SIGNATURE
            | macho::LC_DYLD_EXPORTS_TRIE
            | macho::LC_DYLD_CHAINED_FIXUPS => {
                let (c, _) =
                    pod::from_bytes::<macho::LinkeditDataCommand<LittleEndian>>(&buf[cmd_pos..])
                        .unwrap();
                push_bound(&mut linkedit_bounds, c.dataoff.get(LE), c.datasize.get(LE));
            }
            _ => {}
        }

        cmd_pos += cmdsize;
    }

    // --- Phase 3: Compute LINKEDIT bounding range ---
    let linkedit_seg = segments
        .iter()
        .find(|s| seg_name(&s.name) == "__LINKEDIT")
        .ok_or("No __LINKEDIT segment found")?;
    let linkedit_seg_old_fileoff = linkedit_seg.old_fileoff;
    let linkedit_seg_old_vmaddr = linkedit_seg.vmaddr;

    let (min_off, max_end) = if linkedit_bounds.is_empty() {
        (
            linkedit_seg.old_fileoff as u32,
            (linkedit_seg.old_fileoff + linkedit_seg.old_filesize) as u32,
        )
    } else {
        let min = linkedit_bounds.iter().map(|&(o, _)| o).min().unwrap();
        let max = linkedit_bounds.iter().map(|&(_, e)| e).max().unwrap();
        (min, max)
    };
    let linkedit_extract_size = (max_end - min_off) as u64;

    // --- Phase 4: Compute new file layout ---
    struct NewSegLayout {
        seg_index: usize,
        new_fileoff: u64,
        new_filesize: u64,
        new_vmaddr: u64,
        new_vmsize: u64,
    }

    let mut layouts: Vec<NewSegLayout> = Vec::new();
    let mut cursor: u64 = 0;

    for (i, seg) in segments.iter().enumerate() {
        let name = seg_name(&seg.name);

        if name == "__LINKEDIT" {
            continue;
        }

        if name == "__TEXT" {
            layouts.push(NewSegLayout {
                seg_index: i,
                new_fileoff: 0,
                new_filesize: seg.old_filesize,
                new_vmaddr: seg.vmaddr,
                new_vmsize: seg.vmsize,
            });
            cursor = seg.old_filesize;
        } else {
            let aligned = align_to(cursor, PAGE_SIZE);
            layouts.push(NewSegLayout {
                seg_index: i,
                new_fileoff: aligned,
                new_filesize: seg.old_filesize,
                new_vmaddr: seg.vmaddr,
                new_vmsize: seg.vmsize,
            });
            cursor = aligned + seg.old_filesize;
        }
    }

    // __LINKEDIT last
    let linkedit_idx = segments
        .iter()
        .position(|s| seg_name(&s.name) == "__LINKEDIT")
        .unwrap();
    let linkedit_new_fileoff = align_to(cursor, PAGE_SIZE);
    let linkedit_new_vmaddr = linkedit_seg_old_vmaddr + (min_off as u64 - linkedit_seg_old_fileoff);
    layouts.push(NewSegLayout {
        seg_index: linkedit_idx,
        new_fileoff: linkedit_new_fileoff,
        new_filesize: linkedit_extract_size,
        new_vmaddr: linkedit_new_vmaddr,
        new_vmsize: linkedit_extract_size,
    });

    let total_size = (linkedit_new_fileoff + linkedit_extract_size) as usize;

    // --- Phase 5: Patch the buffer in-place ---

    // 5a: Clear MH_DYLIB_IN_CACHE flag
    {
        let (header, _) = pod::from_bytes_mut::<macho::MachHeader64<LittleEndian>>(&mut buf)
            .map_err(|_| "Failed to parse header for patching")?;
        let flags = header.flags.get(LE);
        header.flags.set(LE, flags & !macho::MH_DYLIB_IN_CACHE);
    }

    // 5b: Patch segments and their sections
    for layout in &layouts {
        let seg = &segments[layout.seg_index];
        let c = seg.cmd_offset;
        let name = seg_name(&seg.name);

        let nsects = {
            let (seg_cmd, _) =
                pod::from_bytes_mut::<macho::SegmentCommand64<LittleEndian>>(&mut buf[c..])
                    .unwrap();
            seg_cmd.fileoff.set(LE, layout.new_fileoff);
            seg_cmd.filesize.set(LE, layout.new_filesize);
            if name == "__LINKEDIT" {
                seg_cmd.vmaddr.set(LE, layout.new_vmaddr);
                seg_cmd.vmsize.set(LE, layout.new_vmsize);
            }
            seg_cmd.nsects.get(LE)
        };

        if name != "__LINKEDIT" {
            let delta = layout.new_fileoff as i64 - seg.old_fileoff as i64;
            let sect_start = c + seg_cmd_size;
            for i in 0..nsects as usize {
                let s_off = sect_start + i * sect_size;
                let (sect, _) =
                    pod::from_bytes_mut::<macho::Section64<LittleEndian>>(&mut buf[s_off..])
                        .unwrap();

                let sect_type = sect.flags.get(LE) & macho::SECTION_TYPE;
                let is_zerofill = sect_type == macho::S_ZEROFILL
                    || sect_type == macho::S_GB_ZEROFILL
                    || sect_type == macho::S_THREAD_LOCAL_ZEROFILL;

                let old_offset = sect.offset.get(LE);
                if !is_zerofill && old_offset != 0 {
                    sect.offset.set(LE, (old_offset as i64 + delta) as u32);
                }

                let old_reloff = sect.reloff.get(LE);
                if old_reloff != 0 {
                    sect.reloff
                        .set(LE, linkedit_new_fileoff as u32 + (old_reloff - min_off));
                }
            }
        }
    }

    // 5c: Patch LINKEDIT-referencing commands (second walk with mutable struct access)
    let linkedit_new = linkedit_new_fileoff as u32;
    let mut cmd_pos = hdr_size;
    for _ in 0..ncmds {
        let (cmd, cmdsize) = {
            let (lc, _) =
                pod::from_bytes::<macho::LoadCommand<LittleEndian>>(&buf[cmd_pos..]).unwrap();
            (lc.cmd.get(LE), lc.cmdsize.get(LE) as usize)
        };

        match cmd {
            macho::LC_SYMTAB => {
                let (c, _) =
                    pod::from_bytes_mut::<macho::SymtabCommand<LittleEndian>>(&mut buf[cmd_pos..])
                        .unwrap();
                patch_linkedit!(c, symoff, nsyms, linkedit_new, min_off);
                patch_linkedit!(c, stroff, strsize, linkedit_new, min_off);
            }
            macho::LC_DYSYMTAB => {
                let (c, _) = pod::from_bytes_mut::<macho::DysymtabCommand<LittleEndian>>(
                    &mut buf[cmd_pos..],
                )
                .unwrap();
                patch_linkedit!(c, tocoff, ntoc, linkedit_new, min_off);
                patch_linkedit!(c, modtaboff, nmodtab, linkedit_new, min_off);
                patch_linkedit!(c, extrefsymoff, nextrefsyms, linkedit_new, min_off);
                patch_linkedit!(c, indirectsymoff, nindirectsyms, linkedit_new, min_off);
                patch_linkedit!(c, extreloff, nextrel, linkedit_new, min_off);
                patch_linkedit!(c, locreloff, nlocrel, linkedit_new, min_off);
            }
            macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY => {
                let (c, _) = pod::from_bytes_mut::<macho::DyldInfoCommand<LittleEndian>>(
                    &mut buf[cmd_pos..],
                )
                .unwrap();
                patch_linkedit!(c, rebase_off, rebase_size, linkedit_new, min_off);
                patch_linkedit!(c, bind_off, bind_size, linkedit_new, min_off);
                patch_linkedit!(c, weak_bind_off, weak_bind_size, linkedit_new, min_off);
                patch_linkedit!(c, lazy_bind_off, lazy_bind_size, linkedit_new, min_off);
                patch_linkedit!(c, export_off, export_size, linkedit_new, min_off);
            }
            macho::LC_FUNCTION_STARTS
            | macho::LC_DATA_IN_CODE
            | macho::LC_CODE_SIGNATURE
            | macho::LC_DYLD_EXPORTS_TRIE
            | macho::LC_DYLD_CHAINED_FIXUPS => {
                let (c, _) = pod::from_bytes_mut::<macho::LinkeditDataCommand<LittleEndian>>(
                    &mut buf[cmd_pos..],
                )
                .unwrap();
                patch_linkedit!(c, dataoff, datasize, linkedit_new, min_off);
            }
            _ => {}
        }

        cmd_pos += cmdsize;
    }

    // --- Phase 6: Assemble output ---
    let mut output_buf = vec![0u8; total_size];

    for layout in &layouts {
        let seg = &segments[layout.seg_index];
        let name = seg_name(&seg.name);

        if name == "__LINKEDIT" {
            // The min_off is a file offset into the cache; convert to vmaddr for lookup
            let linkedit_vmaddr_for_min =
                linkedit_seg_old_vmaddr + (min_off as u64 - linkedit_seg_old_fileoff);
            if let Some((data, data_offset)) =
                cache.data_and_offset_for_address(linkedit_vmaddr_for_min)
            {
                let src_start = data_offset as usize;
                let src_end = src_start + linkedit_extract_size as usize;
                let dst_start = layout.new_fileoff as usize;
                let dst_end = dst_start + linkedit_extract_size as usize;
                if src_end <= data.len() {
                    output_buf[dst_start..dst_end].copy_from_slice(&data[src_start..src_end]);
                } else {
                    let available = data.len() - src_start;
                    output_buf[dst_start..dst_start + available]
                        .copy_from_slice(&data[src_start..]);
                    eprintln!(
                        "Warning: LINKEDIT data truncated (wanted {} bytes, got {})",
                        linkedit_extract_size, available
                    );
                }
            } else {
                return Err("Could not resolve LINKEDIT data address in cache".into());
            }
        } else {
            if layout.new_filesize == 0 {
                continue;
            }
            if let Some((data, data_offset)) = cache.data_and_offset_for_address(seg.vmaddr) {
                let src_start = data_offset as usize;
                let copy_len = layout.new_filesize as usize;
                let src_end = src_start + copy_len;
                let dst_start = layout.new_fileoff as usize;
                let dst_end = dst_start + copy_len;
                if src_end <= data.len() {
                    output_buf[dst_start..dst_end].copy_from_slice(&data[src_start..src_end]);
                } else {
                    let available = data.len() - src_start;
                    output_buf[dst_start..dst_start + available]
                        .copy_from_slice(&data[src_start..]);
                    eprintln!(
                        "Warning: segment {} truncated (wanted {} bytes, got {})",
                        name, copy_len, available
                    );
                }
            } else {
                eprintln!(
                    "Warning: could not resolve data for segment {} at vmaddr 0x{:X}",
                    name, seg.vmaddr
                );
            }
        }
    }

    // Overlay patched header+load_commands at offset 0
    output_buf[..buf.len()].copy_from_slice(&buf);

    // --- Write output file ---
    let output_path = match output {
        Some(p) => p.to_string(),
        None => {
            let basename = Path::new(dylib_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("extracted.dylib");
            basename.to_string()
        }
    };

    let mut f = File::create(&output_path)?;
    f.write_all(&output_buf)?;

    eprintln!(
        "Extracted {} -> {} ({} bytes)",
        dylib_path, output_path, total_size
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to_already_aligned() {
        assert_eq!(align_to(0x4000, PAGE_SIZE), 0x4000);
        assert_eq!(align_to(0x8000, PAGE_SIZE), 0x8000);
    }

    #[test]
    fn test_align_to_rounds_up() {
        assert_eq!(align_to(1, PAGE_SIZE), 0x4000);
        assert_eq!(align_to(0x4001, PAGE_SIZE), 0x8000);
        assert_eq!(align_to(0x7FFF, PAGE_SIZE), 0x8000);
    }

    #[test]
    fn test_align_to_zero() {
        assert_eq!(align_to(0, PAGE_SIZE), 0);
    }

    #[test]
    fn test_seg_name_null_terminated() {
        let mut name = [0u8; 16];
        name[..6].copy_from_slice(b"__TEXT");
        assert_eq!(seg_name(&name), "__TEXT");
    }

    #[test]
    fn test_seg_name_full_length() {
        let name = *b"__LONG_SEG_NAME_";
        assert_eq!(seg_name(&name), "__LONG_SEG_NAME_");
    }

    #[test]
    fn test_seg_name_empty() {
        let name = [0u8; 16];
        assert_eq!(seg_name(&name), "");
    }

    #[test]
    fn test_push_bound_nonzero() {
        let mut bounds = Vec::new();
        push_bound(&mut bounds, 100, 50);
        assert_eq!(bounds, vec![(100, 150)]);
    }

    #[test]
    fn test_push_bound_zero_offset() {
        let mut bounds = Vec::new();
        push_bound(&mut bounds, 0, 50);
        assert!(bounds.is_empty());
    }

    #[test]
    fn test_push_bound_zero_size() {
        let mut bounds = Vec::new();
        push_bound(&mut bounds, 100, 0);
        assert!(bounds.is_empty());
    }

    #[test]
    fn test_push_bound_both_zero() {
        let mut bounds = Vec::new();
        push_bound(&mut bounds, 0, 0);
        assert!(bounds.is_empty());
    }

    #[test]
    fn test_patch_linkedit_rebases_offset() {
        use object::endian::U32;
        #[derive(Debug)]
        struct FakeCmd {
            off: U32<LittleEndian>,
            size: U32<LittleEndian>,
        }
        let mut cmd = FakeCmd {
            off: U32::new(LE, 1000),
            size: U32::new(LE, 200),
        };
        let new_base: u32 = 500;
        let min_off: u32 = 800;
        patch_linkedit!(cmd, off, size, new_base, min_off);
        // new_off = 500 + (1000 - 800) = 700
        assert_eq!(cmd.off.get(LE), 700);
    }

    #[test]
    fn test_patch_linkedit_zeros_stale_offset() {
        use object::endian::U32;
        #[derive(Debug)]
        struct FakeCmd {
            off: U32<LittleEndian>,
            size: U32<LittleEndian>,
        }
        let mut cmd = FakeCmd {
            off: U32::new(LE, 1000),
            size: U32::new(LE, 0),
        };
        patch_linkedit!(cmd, off, size, 500u32, 800u32);
        assert_eq!(cmd.off.get(LE), 0);
    }

    #[test]
    fn test_patch_linkedit_already_zero() {
        use object::endian::U32;
        #[derive(Debug)]
        struct FakeCmd {
            off: U32<LittleEndian>,
            size: U32<LittleEndian>,
        }
        let mut cmd = FakeCmd {
            off: U32::new(LE, 0),
            size: U32::new(LE, 200),
        };
        patch_linkedit!(cmd, off, size, 500u32, 800u32);
        assert_eq!(cmd.off.get(LE), 0);
    }
}
