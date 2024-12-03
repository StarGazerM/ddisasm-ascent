
# ddisasm-ascent

To create a dataset from a binary, you can use the following command :
```bash
ddisasm -I --debug-dir /tmp </path/to/binary> # wait this this command to finish or throw an error
cp /tmp/disassembly/binary.gtirb <dataset_dir>
ddisasm --asm=</path/to/asm> -j 12 --debug-dir <dataset_dir> </path/to/binary>
```

To run souffle on the dataset, you can use the following command :
```bash
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}`pwd`
souffle -L /usr/local/src/ddisasm/build/lib/ -j 12 -o ./extracted.bin ./ddisasm.dl
DDISASM_DEBUG_DIR=</path/to/db>/disassembly DDISASM_GTIRB_MODULE_NAME=<binary> /usr/bin/time -v ./extracted.bin -j 16  -F </path/to/db>/disassembly -D </path/to/result>
```

To run this artifacts you can use :
```bash
cargo build --release
DDISASM_GTIRB_MODULE_NAME=<binary> DDISASM_DEBUG_DIR=./data/disassembly/ LD_LIBRARY_PATH=/usr/local/src/ddisasm/build/lib:$LD_LIBRARY_PATH ./target/release/ddisasm-ascent ./data </path/to/binary>
```
