# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`dsc` — a Rust CLI tool for inspecting macOS/iOS Dyld Shared Cache files. Uses memory-mapped I/O to handle large cache files efficiently.

## Build & Run

```bash
cargo build                # debug build
cargo build --release      # release build
cargo clippy               # lint
cargo fmt                  # format
cargo test                 # no unit tests yet; runs cargo's test harness
```

Manual smoke test against corpus data (corpus/ directory, not checked in):
```bash
./run.sh
```

Run the tool directly:
```bash
cargo run -- images <path-to-dyld-cache>
cargo run -- sections <path> [--module <name>]
cargo run -- symbols <path> [--module <name>]
cargo run -- dump <path> <address> [size]
```

## Architecture

Single-binary CLI with two source files:

- **`src/main.rs`** — CLI parsing (clap derive), cache loading, and all four subcommands (`images`, `sections`, `symbols`, `dump`)
- **`src/utils.rs`** — hex dump formatter

Key pattern: `with_dyld_cache(path, callback)` is a higher-order function that handles opening the main cache file via mmap, discovering and loading all subcache files, parsing via the `object` crate's `DyldCache<LittleEndian>`, then passing the parsed cache to the callback. All command functions receive the parsed cache reference.

## Dependencies

- **clap** (derive) — CLI argument parsing
- **memmap2** — memory-mapped file access
- **object** — parses Mach-O / DyldCache binary formats
