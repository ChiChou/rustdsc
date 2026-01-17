#!/bin/bash

for dir in corpus/* ; do
    dsc=$(ls $dir/*/dyld_shared_cache_* | head -n 1)
    cargo run -- $dsc
done
