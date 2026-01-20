#!/bin/bash
# Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

HOST_ARCH="x86_64-linux-gnu"

print_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --host <host_arch>          Set the host architecture (default: x86_64-linux-gnu)"
    echo "  --with_qmi_prefix <prefix>  Set the QMI prefix"
    echo "  --help                      Display this help message"
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --host)
            HOST_ARCH="$2"
            shift 2
            ;;
        --with_qmi_prefix)
            QMI_PREFIX="$2"
            shift 2
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            echo "Warning: Unknown parameter passed: $1."
            shift 1
            ;;
    esac
done

# print parameters
echo "Host Architecture: $HOST_ARCH"
echo "QMI Prefix: $QMI_PREFIX"

echo "Cleaning up previous build.."
make clean
rm -rf install

echo "Running autoreconf.."
autoreconf --install || { echo "Autoreconf failed"; exit 1; }

echo "Running configure.."
./configure --host=$HOST_ARCH  --with-qmif-prefix=$QMI_PREFIX --prefix=$(pwd)/install || { echo "configure failed"; exit 1; }

echo "Running make.."
make || { echo "make failed"; exit 1; }

make install || { echo "make install failed"; exit 1; }

FILES_TO_CLEAN=(
    aclocal.m4 configure ar-lib config.h config.h.in config.log config.status libtool
    Makefile Makefile.in compile config.guess install-sh missing mkinstalldirs depcomp
    ltmain.sh stamp-h1 config.sub *subs.sh
)
DIRECTORIES_TO_CLEAN=(
    autom4te.cache
    m4
)

for file in "${FILES_TO_CLEAN[@]}"; do
    if [ -f "$file" ]; then
        rm -f "$file"
    fi
done

for dir in "${DIRECTORIES_TO_CLEAN[@]}"; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
    fi
done

make clean

# Clean up bin executables excluding the install directory
find . -type f -name 'time_daemon' ! -path './install/*' -exec rm -f {} +

# Clean up bin executables in subdirectories
#find . -type f -name 'bin' -exec rm -f {} +

# Additional cleanup for .la files and other generated files
find . -name '*.la' -delete
find . -name '*.o' -delete
find . -name '*.lo' -delete
find . -name '*.libs' -type d -exec rm -rf {} +
find . -name '.deps' -type d -exec rm -rf {} +
find . -name '.dir' -type d -exec rm -rf {} +

# Remove Makefile and Makefile.in from subdirectories
find . -name 'Makefile' -exec rm -f {} +
find . -name 'Makefile.in' -exec rm -f {} +

echo "Build completed successfully."
