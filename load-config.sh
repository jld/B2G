#!/bin/bash

if [[ ! -n "$B2G_DIR" ]]; then
  B2G_DIR=$(cd `dirname $0`; pwd)
fi

. "$B2G_DIR/.config"
if [ $? -ne 0 ]; then
	echo Could not load .config. Did you run config.sh?
	exit -1
fi

if [ -f "$B2G_DIR/.userconfig" ]; then
	. "$B2G_DIR/.userconfig"
fi

if [ "${B2G_PROFILING:-0}" != 0 ]; then
    # FIXME: do this in a less bad way
    case $(uname -ms) in
	"Linux x86_64") HOST_TRIPLE=x86_64-linux-gnu ;;
	"Linux i686") HOST_TRIPLE=i686-linux-gnu ;;
	"Darwin x86_64") HOST_TRIPLE=x86_64-apple-darwin ;;
	"Darwin i386") HOST_TRIPLE=i386-apple-darwin ;;
	*) echo "Unknown host platform: $(uname -ms)" >&2; exit 1 ;;
    esac
    # FIXME: all this needs to be conditional for arm targets
    if [ -z "$TARGET_TOOLS_PREFIX" ]; then
	TARGET_TOOLS_PREFIX=${B2G_DIR?}/prebuilt/alt-toolchain/toolchain-4.4.3/${HOST_TRIPLE}/bin/arm-linux-androideabi-
    fi
    export TARGET_TOOLS_PREFIX
    profiling_cflags="-mapcs-frame -mthumb2-fake-apcs-frame -DHAVE_APCS_FRAME"
    export TARGET_EXTRA_GLOBAL_CFLAGS="$profiling_cflags $TARGET_EXTRA_GLOBAL_CFLAGS"
    unset HOST_TRIPLE profiling_cflags
fi
