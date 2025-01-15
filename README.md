# This spdm-dump is a tool to dump SPDM communication message using [libspdm](https://github.com/DMTF/libspdm)

## Feature

1) A tool to dump SPDM communication message that can run in OS environment.

## Document

1) User guide

   The user guide can be found at [user_guide](https://github.com/DMTF/spdm-dump/blob/main/doc/spdm_dump.md)

## Prerequisit

### Build Tool

1) [Visual Studio](https://visualstudio.microsoft.com/) (VS2015 or VS2019 or VS2022)

2) [GCC](https://gcc.gnu.org/) (above GCC5)

3) [LLVM](https://llvm.org/) (LLVM9)

   Download and install [LLVM9](http://releases.llvm.org/download.html#9.0.0). Ensure LLVM9 executable directory is in PATH environment variable.

## Build

### Git Submodule

   spdm_emu uses submodules for libspdm.

   To get a full buildable repo, please use `git submodule update --init --recursive`.
   If there is an update for submodules, please use `git submodule update`.

### Windows Build with CMake

   Use x86 command prompt for ARCH=ia32 and x64 command prompt for ARCH=x64. (TOOLCHAIN=VS2019|VS2015|CLANG)
   ```
   cd spdm-dump
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   nmake copy_sample_key
   nmake
   ```

### Linux Build with CMake

   (TOOLCHAIN=GCC|CLANG)
   ```
   cd spdm-dump
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<mbedtls|openssl> ..
   make copy_sample_key
   make
   ```

## Run Test

### Run spdm_dump

   The tool output is at spdm-dump/build/bin. It can be used to parse the pcap file for offline analysis.

   Please refer to [spdm_dump](https://github.com/DMTF/spdm-dump/blob/main/doc/spdm_dump.md) for detail. 

## Feature not implemented yet

1) Please refer to [issues](https://github.com/DMTF/spdm-dump/issues) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the library and the drivers are subject to change.

