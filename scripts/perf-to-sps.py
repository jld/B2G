#!/usr/bin/env python
import bisect, json, os, subprocess, sys, re
from datetime import datetime
from optparse import OptionParser
import perflegacy

# Constants from include/uapi/linux/perf_event.h:
def to_u64(x):
    return x & 0xFFFFFFFFFFFFFFFF
PERF_CONTEXT_HV           = to_u64(-32)
PERF_CONTEXT_KERNEL       = to_u64(-128)
PERF_CONTEXT_USER         = to_u64(-512)
PERF_CONTEXT_GUEST        = to_u64(-2048)
PERF_CONTEXT_GUEST_KERNEL = to_u64(-2176)
PERF_CONTEXT_GUEST_USER   = to_u64(-2560)
PERF_CONTEXT_MAX          = to_u64(-4095)


GECKO_OBJDIR = os.getenv("GECKO_OBJDIR")
PRODUCT_OUT = os.getenv("PRODUCT_OUT")
TARGET_TOOL = os.getenv("TARGET_TOOLS_PREFIX") or ""
NM = TARGET_TOOL + "nm"
READELF = TARGET_TOOL + "readelf"

def file_exists(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False

class AddrSpace:
    mask = 0xFFFFFFFF
    bucket = 1 << 22
    def __init__(self, copy_of = None):
        self.buckets = { }
        if copy_of:
            for i in copy_of.buckets:
                self.buckets[i] = copy_of.buckets[i][:]
    def mmap(self, start, end, offset, obj):
        start = start & AddrSpace.mask
        end = end & AddrSpace.mask
        for i in xrange(start / AddrSpace.bucket,
                        (end - 1) / AddrSpace.bucket + 1):
            vstart = max(start, i * AddrSpace.bucket)
            vend = min(end, (i + 1) * AddrSpace.bucket)
            voffset = offset + vstart - start
            if i not in self.buckets:
                self.buckets[i] = []
            self.buckets[i].append((vstart, vend, voffset, obj))
    def lookup(self, addr):
        addr = addr & AddrSpace.mask
        i = addr / AddrSpace.bucket
        if i in self.buckets:
            for (start, end, offset, obj) in reversed(self.buckets[i]):
                if start <= addr and addr < end:
                    return (obj, offset + (addr - start))
        return None

class SymTab:
    nm_re = re.compile("(?P<addr>[0-9a-fA-f ]+) (?P<type>[A-Za-z])"
                       + " (?P<name>.*)")
    def __init__(self, objname, nmfile = None,
                 kallsyms = False, addrmap = None):
        def map_addr(addr):
            for (vbase, size, fbase) in addrmap:
                if vbase <= addr and addr < vbase + size:
                    return addr - vbase + fbase
            return None

        self.name = objname
        if nmfile:
            syms = []
            for line in nmfile:
                fields = SymTab.nm_re.match(line)
                addr, kind, name = fields.group('addr', 'type', 'name')
                if " " in addr:
                    continue
                addr = int(addr, 16)
                if addrmap:
                    addr = map_addr(addr)
                    if addr == None:
                        continue
                if kallsyms:
                    name = name.split("\t", 1)
                    mod = name[1] if len(name) > 1 else objname
                    name = name[0]
                else:
                    mod = objname
                # I'm not sure what these are, but we don't want them.
                if name[-2:-1] == "$":
                    continue
                # FIXME: also suppress aliases
                syms.append((addr, kind, name, mod))
            syms.sort()
            self.sym_addrs = map(lambda t: t[0], syms)
            self.syms = syms
        else:
            self.syms = []
            self.sym_addrs = []

    def lookup(self, addr):
        i = bisect.bisect(self.sym_addrs, addr)
        if i == 0:
            return None
        base, kind, name, mod = self.syms[i-1]
        if kind not in "tTW" or name in ["_etext", "_einittext", "_edata"]:
            return None
        return (name, mod, addr - base)

    @staticmethod
    def from_target_path(abspath):
        path = abspath.lstrip("/")
        attempts = []
        if path.startswith("system/b2g/") and GECKO_OBJDIR:
            attempts.append(os.path.join(GECKO_OBJDIR, "dist/bin",
                                         path[len("system/b2g/"):]))
        if PRODUCT_OUT:
            attempts.append(os.path.join(PRODUCT_OUT, "symbols", path))
            attempts.append(os.path.join(PRODUCT_OUT, "root", path))
            attempts.append(os.path.join(PRODUCT_OUT, path))
        for attempt in filter(file_exists, attempts):
            loadcmds = []
            readelf = subprocess.Popen([READELF, "-l", attempt],
                                       stdout = subprocess.PIPE)
            for line in readelf.stdout:
                if not line.startswith("  LOAD "):
                    continue
                fields = line.split()[1:]
                if len(fields) < 5:
                    # Future-proof against 64-bit
                    fields += readelf.stdout.readline().split()
                offset, virtaddr, physaddr, filesize, memsize = \
                    (int(s, 16) for s in fields[:5])
                loadcmds.append((virtaddr, filesize, offset))
            for cmd in [[NM, "-C"], [NM, "-C", "-D"]]:
                symfh = subprocess.Popen(cmd + [attempt],
                                         stdout = subprocess.PIPE)
                tab = SymTab(abspath, symfh.stdout, addrmap = loadcmds)
                symfh.communicate()
                if len(tab.syms) > 0:
                    return tab
        print >>sys.stderr, "warning: no file found for %s" % abspath
        return SymTab(abspath)

        


class PerfRecord:
    def __init__(self, options):
        self.options = options
        self.spaces = {-1: AddrSpace()} # pid => space
        self.pids = {}  # tid => pid
        self.maintid = {} # pid => tid
        self.names = {0: "swapper"} # tid => string
        self.samples = [] # cpu => sample array
        self.files = {} # path => SymTab
        self.shortened = {} # long => short
        self.last_short = [] # counter, as list of chars
        if options.kallsyms:
            with file(options.kallsyms) as ksfile:
                self.kallsyms = SymTab("[kernel]", ksfile, kallsyms = True)
        else:
            self.kallsyms = None
        self.jsallsyms = {}

    def note_thread(self, pid, tid):
        self.pids[tid] = pid
        if pid not in self.maintid or self.maintid[pid] > tid:
            # Apparently we can get samples with tid 0 and a real pid?
            if tid != 0 or pid == 0:
                self.maintid[pid] = tid

    def shorten(self, longname):
        if longname not in self.shortened:
            self._inc_shorten()
            self.shortened[longname] = "".join(self.last_short)
        return self.shortened[longname]

    def _inc_shorten(self):
        for i in xrange(len(self.last_short)):
            n = ord(self.last_short[i])
            if n < 126:
                n = n + 1
                if n == 34 or n == 92:
                    n = n + 1
                self.last_short[i] = chr(n)
                return
            self.last_short[i] = chr(33)
        self.last_short.append(chr(33))

    def _read_jsallsyms(self, pid):
        if not self.options.jsallsyms:
            return None
        path = "%s/jsallsyms-%d" % (self.options.jsallsyms, pid)
        if not file_exists(path):
            return None
        with open(path) as fh:
            tab = SymTab("JS in pid %d" % pid, nmfile = fh, kallsyms = True)
            if tab.syms:
                return tab
            else:
                return None

    def get_jsallsyms(self, pid):
        if pid not in self.jsallsyms:
            self.jsallsyms[pid] = self._read_jsallsyms(pid)
        return self.jsallsyms[pid]

    def read_dump(self, src):
        for rec in src:
            kind = rec['type']
            if kind == 'sample':
                self.handle_sample(rec)
            elif kind == 'mmap':
                self.handle_mmap(rec)
            elif kind == 'comm':
                self.handle_comm(rec)
            elif kind == 'fork':
                self.handle_fork(rec)

    def handle_mmap(self, rec):
        pid = rec['pid']
        addr = rec['addr']
        maplen = rec['len']
        offset = rec['offset']
        name = rec['filename']
        if pid == -1:
            # We're going to use kallsyms.
            if not self.kallsyms:
                return
            if name.startswith("[kernel."):
                # The kernel-only entry covers the entire kernel
                # space; restrict it to just where there are symbols.
                # Note that there will be _etext/_einittext at the end
                # of the text, so using the start of the last symbol
                # is safe.
                #
                # This should exclude modules, since they're mapped
                # separately, but doesn't yet; it's harmless as long
                # as they're recorded after the kernel entry, since
                # they'll override it in the AddrSpace, but could make
                # things slightly more efficient -- and might avoid
                # falsely matching corrupt addresses in the space
                # between the kernel and modules.  So, FIXME.
                addr = self.kallsyms.sym_addrs[0]
                maplen = self.kallsyms.sym_addrs[-1] - addr
            offset = addr
            symtab = self.kallsyms
        else:
            if name not in self.files:
                if name[:1] == "/" and name[:2] != "//":
                    self.files[name] = SymTab.from_target_path(name)
                else:
                    self.files[name] = SymTab(name)
            symtab = self.files[name]
        if pid not in self.spaces:
            self.spaces[pid] = AddrSpace()
            js = self.get_jsallsyms(pid)
            if js:
                self.spaces[pid].mmap(js.sym_addrs[0], js.sym_addrs[-1] + 1,
                                      js.sym_addrs[0], js)
        self.spaces[pid].mmap(addr, addr + maplen, offset, symtab)

    def handle_comm(self, rec):
        self.names[rec['tid']] = rec['comm']
        # FIXME: how do we distinguish an exec from a thread name change?

    def handle_fork(self, rec):
        ppid = rec['ppid']
        ptid = rec['ptid']
        cpid = rec['pid']
        ctid = rec['tid']
        self.note_thread(cpid, ctid)
        if ppid in self.spaces:
            self.spaces[cpid] = AddrSpace(self.spaces[ppid])
        self.names[ctid] = self.names[ptid]

    def handle_sample(self, rec):
        cpu = rec['cpu']
        msec = rec['time'] / 1e6
        pid = rec['pid']
        tid = rec['tid']
        sample_ip = rec['ip']
        self.note_thread(pid, tid)
        frames = []
        context = None
        i = -1
        for pc in rec['ips']:
            i = i + 1
            if pc >= PERF_CONTEXT_MAX:
                context = pc
                if i == 0 and pc == PERF_CONTEXT_USER:
                    # Linux/arm has a bug where the user-mode PC
                    # isn't recorded in the stack trace.  If the
                    # sample hit while in user mode, we can get it
                    # from the PERF_SAMPLE_IP instead.
                    pc = sample_ip
                else:
                    continue
            if context == PERF_CONTEXT_USER:
                # FIXME: if not on arm, or on fixed arm, try to
                # detect duplicate top frame.  Sigh.
                space = self.spaces.get(pid, None)
            elif context == PERF_CONTEXT_KERNEL:
                space = self.spaces[-1]
            else:
                if context:
                    print >>sys.stderr, \
                        ("warning: unknown frame context (__u64)%d"
                         % (context - (1 << 64)))
                else:
                    print >>sys.stderr, \
                        "warning: frame with no context" % pc
                space = None
            fileinfo = space and space.lookup(pc)
            if fileinfo:
                symtab, offset = fileinfo
                syminfo = symtab.lookup(offset)
                if syminfo:
                    name, mod, symoffset = syminfo
                    frames.append("%s (in %s)" % (name, mod))
                else:
                    frames.append("%#x (in %s)" % (offset, symtab.name))
            else:
                # If the address wasn't even mapped, it's probably junk.
                if self.options.clean:
                    continue
                else:
                    frames.append("%#x" % pc)
        # Post-processing:
        if self.options.clean:
            # Make empty stacks stand out & not be self samples on the root.
            if len(frames) == 0:
                frames = ["Corrupt Stack"]
            # pthread_create, in the child, has a false caller that varies.
            # In the parent, we assume it can't be the second-lowest frame.
            if len(frames) >= 2 \
                    and frames[-2].startswith("pthread_create "):
                frames[-1:] = []
        frames.append("%s (in tid %d)"
                      % (self.names.get(tid, "???"), tid))
        frames.append("%s (in pid %d)"
                      % (self.names.get(self.maintid[pid], "???"), pid))
        frames.reverse()
        while cpu >= len(self.samples):
            self.samples.append([])
        self.samples[cpu].append({ 'time': msec,
                              'frames': map(self.shorten, frames) })

    def write_json(self, fh):
        profile = { 'threads': [{ 'name': "CPU %d" % cpu,
                                  'samples': self.samples[cpu] }
                                for cpu in xrange(len(self.samples))] }
        unshorten = dict((self.shortened[l], l) for l in self.shortened)
        json.dump({ 'format': 'profileJSONWithSymbolicationTable,1',
                    'profileJSON': profile,
                    'symbolicationTable': unshorten },
                  fh, separators = (',', ':'))

def main():
    op = OptionParser()
    op.add_option("-k", "--kallsyms", dest='kallsyms', metavar="FILE",
                  help=("read kernel symbols (in /proc/kallsyms format)"
                        + " from FILE"))
    op.add_option("-j", "--jsallsyms-dir", dest='jsallsyms', metavar="DIR",
                  help=("read JavaScript pseudo-symbols from files in DIR"))
    op.add_option("-N", "--noisy", dest='clean',
                  default=True, action='store_false',
                  help="don't collapse apparently-corrupt stacks")
    op.add_option("-p", "--perf", dest='perf', metavar="COMMAND",
                  default="perf",
                  help="specify name or path of perf(1) executable")
    op.add_option("-i", "--input", dest='input', metavar="FILE",
                  default="perf.data",
                  help="read perf records from FILE; \"-\" means stdin")
    op.add_option("-D", "--use-dump", dest='use_dump', action='store_true',
                  help=("accept input in |perf report -D| text dump format"
                        + " instead of a binary perf.data file"))

    (options, args) = op.parse_args()

    src = perflegacy.ReportParser(options.input, 
                                  perfcmd = options.perf,
                                  is_dump = options.use_dump)
    record = PerfRecord(options)
    record.read_dump(src)

    filename = datetime.now().strftime("perf_%Y%m%d_%H%M%S.txt")
    print >>sys.stderr, "Writing profile to %s" % filename
    with open(filename, "w") as outfile:
        record.write_json(outfile)
    return 0

if __name__ == '__main__':
    exit(main())
