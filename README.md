<!--
Copyright (c) 2025 LG Electronics, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

<!-- omit from toc -->
# oscms-asn1c-codecs

This repository provides a concrete implementation of the [abstract CODECS API](https://github.com/OpenSCMS/oscms-codecs-api) for the OpenSCMS stack based on CODECs produced by transpiling the official IEEE ASN.1 definitions using the open-source ASN1C transpiler.

At present, the API (and therefore this implementation) is restricted to only those entities sent or received by the OpenSCMS server. Thus, for an SPDU which is only ever sent by the server, there will be an encode function but no matching decode function.

<!-- omit from toc -->
## Table of Contents

- [Development](#development)
  - [Installing Dependencies](#installing-dependencies)
  - [Using Docker](#using-docker)
  - [Getting the Code](#getting-the-code)
  - [Building the code](#building-the-code)
  - [Running Unit Tests](#running-unit-tests)
  - [Running Valgrind](#running-valgrind)
- [Contributing](#contributing)
- [License](#license)

## Development

We assume a debian-based development environment, ideally Ubuntu 24.04 or newer.

### Installing Dependencies

This library has no external dependencies. However, you will need a set of tools

```bash
sudo apt-get -qy install \
    build-essential \
    clang-format-18 \
    cmake \
    cppcheck \
    curl \
    git \
    gzip \
    valgrind \
    wget
```

### Using Docker

Alternatively, you can use the docker file provided in the [oscms-ci-docker](https://github.com/OpenSCMS/oscms-ci-docker) repository. This is the image used for all CI jobs for the C-language repositories during the initial development.

Clone the repository and build the image as follows

```bash
git clone git@github.com:OpenSCMS/oscms-ci-docker.git
cd oscms-ci-docker
docker build -t oscms-ci-docker . -f openscms-ci.dockerfile
```

Now change to the directory where you cloned this repository and run the container thus

```bash
docker run -ti --rm --volume $PWD:/WORK --user $(id -u):$(id -g) \
       oscms-ci-docker
```

This will place you in a `bash` shell within the container, with your cloned source available at `/WORK`. Your user inside the container will have the same group and user id as on your host, so any changes you make will have the correct permissions.

It should also be possible to use this image as a `VS Code` development container. The development team has not used it in this way, so if it doesn't work ... contributions are welcome.

### Getting the Code

The Open SCMS stack makes heavy use of submodules. Therefore, the clone command should ensure it pulls down all sub modules as follows.

```bash
git clone --recurse-submodules git@github.com:OpenSCMS/oscms-asn1c-codecs.git
```

Obviously, replace the URL with your own if you are cloning a fork.

Due to the use of relative submodule paths, if you are going to fork one repository you will need to fork them all. The alternative is for you to modify the paths in `.gitmodules`, but **DO NOT** commit these changes. Such a pull request will not be accepted.

The list of repositories, and their relative submodule dependencies is as follows

- [OpenSCMS](<https://github.com/OpenSCMS/OpenSCMS>)
  - [oscms-codecs-bridge](<https://github.com/OpenSCMS/oscms-codecs-bridge>)
    - [oscms-asn1c-codecs](<https://github.com/OpenSCMS/oscms-asn1c-codecs>)
      - [oscms-codecs-api](<https://github.com/OpenSCMS/oscms-codecs-api>)
      - [oscms-asn1c-generated](<https://github.com/OpenSCMS/oscms-asn1c-generated>)
        - [etsi_ts103097-asn](<https://github.com/OpenSCMS/etsi_ts103097-asn>)
        - [ieee1609dot2dot1-asn](<https://github.com/OpenSCMS/ieee1609dot2dot1-asn>)

### Building the code

All C code is built using `CMake` and the `CMake` scripts will enforce out-of-source builds.

After cloning, create a build directory. We usually use `BUILD` directly in the repository root (it's included in the `.gitignore`), but feel free to put it anywhere convenient.

Change to your build directory and configure and build as follows

```bash
cmake .. # Or the path to your repository root
make
```

This will compile and link a Debug build and include all unit tests.

All CMake scripts support a common set of options and command line definitions.

| Option | Default | Description |
| :--- | :--- | :--- |
| BUILD_TESTS | On | Enables or disables the building of the unit tests |
| CMAKE_BUILD_TYPE | Debug | Defines the build type. Acceptable values are Debug or Release. This primarily affects debug symbols and optimization levels. |
| EXTRA_MEMCHECK_OPTIONS | empty | Allows the specification of additional arguments to `valgrind`|
| RUN_CPPCHECK | On | Enables or disables running `cppcheck` on all code during the build. |

This repository supports an additional option, `ENABLE_ASN1C_DEBUG`, which defaults to `Off'. If defined as 'On', it enables extensive debugging logs from the generated CODECs. This is only really useful as a last resort, when you suspect a fault in the generated code, as it will literally swamp you in logs.

### Running Unit Tests

After building the code (with `BUILD_TESTS` set to `On`) from the build directory, simply enter

```bash
make test
```

Alternatively, you can run them directly with `ctest`

```bash
ctest <options>
```

Which allows you to do things like select specific tests. See the [`CTest` documentation](<https://cmake.org/cmake/help/latest/manual/ctest.1.html>) for details.

### Running Valgrind

From the build directory, run `CTest` with the `memcheck` option

```bash
ctest -T memcheck
```

By default the following `valgrind` options will be specified (in addition to those injected by `CMake` itself)

`-tool=memcheck --leak-check=full --num-callers=50 --show-reachable=yes`

You can specify additional options when configuring using the `EXTRA_MEMCHECK_OPTIONS` variable. For example, to generate suppressions in the log files and track the origin of allocations

```bash
cmake .. \
      -DEXTRA_MEMCHECK_OPTIONS="--gen suppressions=yes --track-origins=yes"
```

The log files will appear in the `Testing/Temporary` directory with names of the form `MemoryChecker.<#>.log` where `#` is the test number. The complete set of results will be in  a log file with `#` being the total number of tests.

## Contributing

Contributions are welcome. Please see the [CONTRIBUTING file](https://github.com/OpenSCMS/.github/blob/main/CONTRIBUTING.md) for details, including the Code of Conduct and C Style Guide.

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE file](./LICENSE) for details.
