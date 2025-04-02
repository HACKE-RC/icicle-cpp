# Icicle
[Icicle](https://github.com/icicle-emu/icicle-emu) is an experimental fuzzing-specific, multi-architecture emulation framework.

## C/C++ Bindings
This project aims to provide C/C++ bindings for the icicle emulator. I'd also like to write full on documentation on this soon.

## Usage
Using these bindings is as simple as compiling the static library using cargo and then including it in your project using your compiler or make, cmake, etc.
If you just want the library and the header file, you can download it from the [releases page](https://github.com/HACKE-RC/icicle-cpp/tags)

### Compilation
Getting the static library is as simple as
```sh
git clone https://github.com/HACKE-RC/icicle-cpp
cd icicle-cpp
cd src
cargo build     # you can use cargo build --release if you want the release build
```

The static library will now be built in `icicle-cpp/src/target/<build_type>/libicicle.a`. Here, <build_type> will be `debug` if you do not use the `--release` flag with cargo
and `release` if you do.
