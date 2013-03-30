#!/bin/bash
set -e
: ${B2G_DIR:=$(cd "$(dirname "$0")" && pwd)}
. "$B2G_DIR/load-config.sh"
set -u

PATH=$PATH:$B2G_DIR/out/host/linux-x86/bin
: ${ADB:=adb}
: ${PRODUCT_OUT:=$B2G_DIR/out/target/product/$DEVICE}
: ${TARGET_TRIPLE:=arm-linux-androideabi}
# FIXME: do this in a less bad way
case $(uname -ms) in
    "Linux x86_64") HOST_TRIPLE=x86_64-linux-gnu ;;
    "Linux i686") HOST_TRIPLE=i686-linux-gnu ;;
    *) echo "Unknown host platform: $(uname -ms)" >&2; exit 1 ;;
esac

host_perf=$B2G_DIR/prebuilt/alt-toolchain/perf/$HOST_TRIPLE-perf
target_perf=$B2G_DIR/prebuilt/alt-toolchain/perf/$TARGET_TRIPLE-perf

perftmp=$PRODUCT_OUT/perf.tmp
mkdir -p "$perftmp"
symfs=$perftmp/symfs
kallsyms=$perftmp/kallsyms
bootstamp=$perftmp/bootstamp

case $1 in
    report)
	shift
	if ! [ -d "$symfs" ]; then
	    # FIXME: need a way to clobber this when it's stale
	    mkdir "$symfs"
	    (   cd "$PRODUCT_OUT/"
		find system -type f -print
		cd root
		find . -type f -print
	    ) | while read item; do
		echo "Making symfs link for $item" >&2
		mkdir -p "$symfs/${item%/*}"
		gecko_src=$GECKO_OBJDIR/dist/bin/${item#system/b2g/}
		symbol_src=$PRODUCT_OUT/symbols/$item
		stripped_src=$PRODUCT_OUT/$item
		if [ -e "$gecko_src" ]; then
		    ln -ns "$gecko_src" "$symfs/$item"
		elif [ -e "$symbol_src" ]; then
		    ln -ns "$symbol_src" "$symfs/$item"
		else
		    ln -ns "$stripped_src" "$symfs/$item"
		fi
	    done
	fi
	"$host_perf" report --symfs "$symfs" --kallsyms "$kallsyms" \
	    -i "$perftmp/perf.data" "$@"
	;;

    record)
	shift
	need_perf=$("$ADB" shell 'test -e /cache/perf; echo $?' | tr -d \\r)
	if [ "$need_perf" -ne 0 ]; then
	    "$ADB" push "$target_perf" /cache/perf
	fi
	{   echo 'cd /cache && ./perf record '"$*"' & perf_pid=$!';
	    {   sleep 0.25
		echo >&2
		echo >&2
		echo "Press Enter to stop recording..." >&2
	    } &
	    # XXX could this be done with an INT trap?
	    # Or would that kill the adb as well?
	    read
	    echo 'kill -INT -$perf_pid; wait $perf_pid; exit'
	} | "$ADB" shell
	"$ADB" pull /cache/perf.data "$perftmp"/
	# Refresh kallsyms if /proc/1 mtime (== boot time) changes.
	# Note: This may not be right if modules are dynamically loaded.
	proc1_info=$("$ADB" shell ls -ld /proc/1)
	touch "$bootstamp"
	if [ "$proc1_info" != "$(cat "$bootstamp")" ]; then
	    echo "$proc1_info" > "$bootstamp"
	    "$ADB" pull /proc/kallsyms "$perftmp"/
	fi
	;;

    sps)
	shift
	export GECKO_OBJDIR PRODUCT_OUT
	"$B2G_DIR/scripts/perf-to-sps.py" \
	    --perf "$host_perf" --kallsyms "$kallsyms" \
	    -i "$perftmp/perf.data" "$@"
	;;

    record-sps)
	shift
	"$0" record -a -g "$@"
	"$0" sps
	;;

    *)
	echo "$0: unhandled perf command \"$1\"" >&2
	exit 1
esac

