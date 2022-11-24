Bluetooth HCI protocol analysis
-----------------------

### Build

```
cmake -B build -GNinja -DCMAKE_TOOLCHAIN_FILE=$EMSCRIPTEN/cmake/Modules/Platform/Emscripten.cmake
```

### Usage

```
ln -s build/btparser.js web/btparser.js
ln -s build/btparser.wasm web/btparser.wasm
python -m http.server
```

### Demo
https://openbody.org/main/btparser
