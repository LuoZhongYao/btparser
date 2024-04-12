Bluetooth HCI protocol analysis
-----------------------

### Build

```
cmake -B build -GNinja -DCMAKE_TOOLCHAIN_FILE=$EMSCRIPTEN/cmake/Modules/Platform/Emscripten.cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

### Usage

```
cp build/btmon.js web/btmon.js
cp build/btmon.wasm web/btmon.wasm
python -m http.server
```

### Demo
https://openbody.org/main/btparser
