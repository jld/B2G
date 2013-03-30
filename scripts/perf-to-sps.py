#!/usr/bin/env python
import bisect, json, os, subprocess, sys, re, threading
from datetime import datetime
from optparse import OptionParser

GECKO_OBJDIR = os.getenv("GECKO_OBJDIR")
PRODUCT_OUT = os.getenv("PRODUCT_OUT")
TARGET_TOOL = os.getenv("TARGET_TOOLS_PREFIX") or ""
NM = TARGET_TOOL + "nm"

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
    def __init__(self, objname, nmfile = None, kallsyms = False):
        self.name = objname
        if nmfile:
            syms = []
            for line in nmfile:
                fields = SymTab.nm_re.match(line)
                addr, kind, name = fields.group('addr', 'type', 'name')
                if " " in addr or name[0] == "$":
                    continue
                addr = int(addr, 16)
                if kallsyms:
                    name = name.split("\t", 1)
                    mod = name[1] if len(name) > 1 else objname
                    name = name[0]
                else:
                    mod = objname
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
            ### FIXME: deal with offset!=virtaddr segments.
            ### Something like this:
            # phdrs = []
            # loadcmds = subprocess.Popen([READELF, "-l", attempt], stdout=PIPE)
            # for line in loadcmds.stdout:
            #     if not line.startswith("  LOAD "):
            #         return
            #     phdrs.append([int(s, 16) for s in line.split()[1:6]])
            for cmd in [[NM, "-C"], [NM, "-C", "-D"]]:
                symfh = subprocess.Popen(cmd + [attempt],
                                         stdout = subprocess.PIPE)
                tab = SymTab(abspath, symfh.stdout)
                symfh.communicate()
                if len(tab.syms) > 0:
                    return tab
        print >>sys.stderr, "warning: no file found for %s" % abspath
        return SymTab(abspath)

class PerfRecord:
    recordline_re = re.compile("(?P<cpu>[0-9]+) (?P<nsec>[0-9]+)"
                               + " 0x[0-9a-f]+ \[0x[0-9a-f]+\]: "
                               + "PERF_RECORD_(?P<name>[A-Z0-9_]+)"
                               + "(?P<thing>\(.*?\)|[^:]*): ?(?P<rest>[^ ].*)")
    mapinfo_re = re.compile("\[(?P<addr>0x[0-9a-f]+)\((?P<len>0x[0-9a-f]+)\)"
                            +" @ (?P<offset>[0-9]+|0x[0-9a-f]+)\]")
    frame_re = re.compile("\.\.\.\.\. *[0-9]+: (?P<pc>[0-9a-f]+)")

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

    def note_thread(self, pid, tid):
        self.pids[tid] = pid
        if pid not in self.maintid or self.maintid[pid] > tid:
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

    def read_dump(self, fh):
        for line in fh:
            header = PerfRecord.recordline_re.match(line)
            if header:
                self.handle_record(fh, header)

    def handle_record(self, fh, header):
        kind = header.group('name')
        if kind == 'MMAP':
            self.handle_mmap(header)
        elif kind == 'COMM':
            self.handle_comm(header)
        elif kind == 'FORK':
            self.handle_fork(header)
        elif kind == 'EXIT':
            # Not handling this yet...
            pass
        elif kind == 'SAMPLE':
            self.handle_sample(fh, header)
        else:
            print >>sys.stderr, ("Unhandled %s record" % kind)

    def handle_mmap(self, header):
        pid, tid = map(int, header.group('thing').split("/"))
        mapinfo_str, name = header.group('rest').split(": ")
        mapinfo = PerfRecord.mapinfo_re.match(mapinfo_str)
        if not mapinfo:
            return
        addr = int(mapinfo.group('addr'), 16)
        maplen = int(mapinfo.group('len'), 16)
        offset = int(mapinfo.group('offset'), 16)
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
        self.spaces[pid].mmap(addr, addr + maplen, offset, symtab)

    def handle_comm(self, header):
        (name, tid) = header.group('rest').rsplit(":", 1)
        tid = int(tid)
        self.names[tid] = name
        # FIXME: how do we distinguish an exec from a thread name change?

    def handle_fork(self, header):
        ppid, ptid = map(int, header.group('rest').strip("()").split(":"))
        cpid, ctid = map(int, header.group('thing').strip("()").split(":"))
        self.note_thread(cpid, ctid)
        if ppid in self.spaces:
            self.spaces[cpid] = AddrSpace(self.spaces[ppid])
        self.names[ctid] = self.names[ptid]

    def handle_sample(self, fh, header):
        cpu = int(header.group('cpu'))
        msec = int(header.group('nsec')) / 1e6
        pid, tid = map(int, header.group('rest').split(": ")[0].split("/"))
        self.note_thread(pid, tid)
        frames = []
        for line in fh:
            if line == "\n":
                break
            frame = PerfRecord.frame_re.match(line)
            if frame:
                pc = int(frame.group('pc'), 16)
                # What are these addresses doing at the top of the stack?
                if pc >= 0xfffffffff000:
                    continue
                fileinfo = ((pid in self.spaces and
                             self.spaces[pid].lookup(pc)) or
                            self.spaces[-1].lookup(pc))
                if fileinfo:
                    symtab, offset = fileinfo
                    syminfo = symtab.lookup(offset)
                    if syminfo:
                        name, mod, symoffset = syminfo
                        frames.append("%s (in %s)" % (name, mod))
                    else:
                        frames.append("%#x (in %s)" % (offset, symtab.name))
                else:
                    frames.append("%#x" % pc)

        if self.options.clean:
            usertop = 0
            for i in reversed(xrange(len(frames))):
                if " (in [kernel" in frames[i]:
                    usertop = i + 1
                    break
            # If all the "user" frames were wild, assume garbage
            # Exception: a non-empty kernel-only stack
            if (usertop != len(frames) or usertop == 0) and \
                    all(" (in " not in f for f in frames[usertop:]):
                # Assume any unresolved kernel addresses are also bad.
                # Sadly, there may also be garbage that landed on a symbol.
                if self.kallsyms:
                    while usertop > 0 and frames[usertop - 1].startswith("0x"):
                        usertop -= 1
                frames[usertop:] = ["Corrupt Stack"]
            # pthread_create always has a false parent
            if len(frames) - usertop >= 2 \
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

    record = PerfRecord(options)
    if options.use_dump:
        if options.input == "-":
            record.read_dump(sys.stdin)
        else:
            with open(options.input) as infile:
                record.read_dump(infile)
    else:
        command = [options.perf, "report", "-D", "-i", options.input]
        perf = subprocess.Popen(command,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE)
        errbuf = []
        def errloop():
            for line in perf.stderr:
                errbuf.append(line)
        errthread = threading.Thread(target = errloop)
        errthread.daemon = True
        errthread.start()
        record.read_dump(perf.stdout)
        errthread.join()
        perf.communicate()
        if perf.returncode != 0:
            print >>sys.stderr, "+ " + " ".join(command)
            if len(errbuf) > 0 and errbuf[-1][-1:] != "\n":
                errbuf[-1] += "\n"
            for line in errbuf:
                sys.stderr.write(line)
            print >>sys.stderr, ("perf exited with status %d"
                                 % perf.returncode)
            return 1

    filename = datetime.now().strftime("perf_%Y%m%d_%H%M%S.txt")
    print >>sys.stderr, "Writing profile to %s" % filename
    with open(filename, "w") as outfile:
        record.write_json(outfile)
    return 0

if __name__ == '__main__':
    exit(main())
