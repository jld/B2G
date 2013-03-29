import bisect, json, os, subprocess, sys, re
from datetime import datetime
from optparse import OptionParser

recordline_re = re.compile("(?P<cpu>[0-9]+) (?P<nsec>[0-9]+) 0x[0-9a-f]+ "
                           +"\[0x[0-9a-f]+\]: PERF_RECORD_(?P<name>[A-Z0-9_]+)"
                           +"(?P<thing>\(.*?\)|[^:]*): ?(?P<rest>[^ ].*)")
mapinfo_re = re.compile("\[(?P<addr>0x[0-9a-f]+)\((?P<len>0x[0-9a-f]+)\)"
                        +" @ (?P<offset>[0-9]+|0x[0-9a-f]+)\]")
frame_re = re.compile("\.\.\.\.\. *[0-9]+: (?P<pc>[0-9a-f]+)")

OBJDIR_GECKO = os.getenv("OBJDIR_GECKO")
PRODUCT_OUT = os.getenv("PRODUCT_OUT")
TARGET_TOOL = os.getenv("TARGET_TOOLS_PREFIX") or ""
NM = TARGET_TOOL + "nm"

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
    def lookup(self, addr):
        i = bisect.bisect(self.sym_addrs, addr)
        if i == 0:
            return None
        base, kind, name, mod = self.syms[i-1]
        if kind not in "tTW" or name in ["_etext", "_einittext", "_edata"]:
            return None
        return (name, mod, addr - base)


kallsyms = None
spaces = {-1: AddrSpace()} # pid => AddrSpace
pids = {}  # tid => pid
maintid = {} # pid => tid
names = {0: "swapper"} # tid => string
samples = [] # cpu => sample array
files = {} # path => SymTab
shortened = {}
last_short = []

op = OptionParser()
op.add_option("-k", "--kallsyms", dest='kallsyms', metavar="FILE",
              help="read kernel symbols (in /proc/kallsyms format) from FILE")
op.add_option("-N", "--noisy", dest='clean',
              default=True, action='store_false',
              help="don't collapse apparently-corrupt stacks")
(options, args) = op.parse_args()

if options.kallsyms:
    with file(options.kallsyms) as ksfile:
        kallsyms = SymTab("[kernel]", ksfile, kallsyms = True)

def exists(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False

def get_symbols(abspath):
    path = abspath.lstrip("/")
    attempts = []
    if path.startswith("system/b2g/") and OBJDIR_GECKO:
        attempts.append(os.path.join(OBJDIR_GECKO, "dist/bin",
                                     path[len("system/b2g/"):]))
    if PRODUCT_OUT:
        attempts.append(os.path.join(PRODUCT_OUT, "symbols", path))
        attempts.append(os.path.join(PRODUCT_OUT, "root", path))
        attempts.append(os.path.join(PRODUCT_OUT, path))
    for attempt in filter(exists, attempts):
        ### FIXME: deal with offset!=virtaddr segments.
        ### Something like this:
        # phdrs = []
        # with subprocess.Popen(READELF, "-l", attempt) as loadfh:
        #     for line in loadfh:
        #         if not line.startswith("  LOAD "):
        #             continue
        #         phdrs.append([int(s, 16) for s in line.split()[1:6]])
        for cmd in [[NM, "-C"], [NM, "-C", "-D"]]:
            symfh = subprocess.Popen(cmd + [attempt],
                                     stdout = subprocess.PIPE)
            tab = SymTab(abspath, symfh.stdout)
            symfh.communicate()
            if len(tab.syms) > 0:
                return tab
    return SymTab(abspath)

def note_thread(pid, tid):
    pids[tid] = pid
    if pid not in maintid or maintid[pid] > tid:
        maintid[pid] = tid

def shorten(longname):
    if longname not in shortened:
        inc_shorten()
        shortened[longname] = "".join(last_short)
    return shortened[longname]

def inc_shorten():
    for i in xrange(len(last_short)):
        n = ord(last_short[i])
        if n < 126:
            n = n + 1
            if n == 34 or n == 92:
                n = n + 1
            last_short[i] = chr(n)
            return
        last_short[i] = chr(33)
    last_short.append(chr(33))

for line in sys.stdin:
    header = recordline_re.match(line)
    if not header:
        continue
    kind = header.group('name')
    if kind == 'MMAP':
        pid, tid = map(int, header.group('thing').split("/"))
        mapinfo_str, name = header.group('rest').split(": ")
        mapinfo = mapinfo_re.match(mapinfo_str)
        if not mapinfo:
            continue
        addr = int(mapinfo.group('addr'), 16)
        maplen = int(mapinfo.group('len'), 16)
        offset = int(mapinfo.group('offset'), 16)
        if pid == -1:
            # We're going to use kallsyms.
            if not kallsyms:
                continue
            if name.startswith("[kernel."):
                # This entry is just weird; do hacks to it.
                # (Needs fixed to exclude modules.)
                addr = kallsyms.sym_addrs[0]
                maplen = kallsyms.sym_addrs[-1] - addr
            offset = addr
            symtab = kallsyms
        else:
            if name not in files:
                files[name] = get_symbols(name) 
            symtab = files[name]
        if pid not in spaces:
            spaces[pid] = AddrSpace()
        print "Mapping pid %d addr %#x len %#x offset %#x thing %s" % \
            (pid, addr, maplen, offset, symtab.name)
        spaces[pid].mmap(addr, addr + maplen, offset, symtab)
    elif kind == 'COMM':
        (name, tid) = header.group('rest').rsplit(":", 1)
        tid = int(tid)
        names[tid] = name
        # FIXME: how do we distinguish an exec from a thread name change?
    elif kind == 'FORK':
        ppid, ptid = map(int, header.group('rest').strip("()").split(":"))
        cpid, ctid = map(int, header.group('thing').strip("()").split(":"))
        note_thread(cpid, ctid)
        if ppid in spaces:
            spaces[cpid] = AddrSpace(spaces[ppid])
        names[ctid] = names[ptid]
    elif kind == 'EXIT':
        # Not handling this yet...
        pass
    elif kind == 'SAMPLE':
        cpu = int(header.group('cpu'))
        msec = int(header.group('nsec')) / 1e6
        pid, tid = map(int, header.group('rest').split(": ")[0].split("/"))
        note_thread(pid, tid)
        frames = []
        for line in sys.stdin:
            if line == "\n":
                break
            frame = frame_re.match(line)
            if frame:
                pc = int(frame.group('pc'), 16)
                # What are these addresses doing at the top of the stack?
                if pc >= 0xfffffffff000:
                    continue
                fileinfo = (pid in spaces and spaces[pid].lookup(pc)) \
                    or spaces[-1].lookup(pc)
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
        if options.clean and all(" (in " not in f for f in frames):
            frames = ["Corrupt Stack"]
        frames.append("%s (in tid %d)" % (names.get(tid, "???"), tid))
        frames.append("%s (in pid %d)" % (names.get(maintid[pid], "???"), pid))
        frames.reverse()
        while cpu >= len(samples):
            samples.append([])
        samples[cpu].append({ 'time': msec,
                              'frames': map(shorten, frames) })
    else:
        print >>sys.stderr, ("Unhandled %s record" % kind)

timestamp = datetime.now().strftime("%H%M")
with open("perf_%s.txt" % timestamp, "w") as io:
    json.dump({ 'format': 'profileJSONWithSymbolicationTable,1',
                'profileJSON': { 'threads': [{ 'name': "CPU %d" % cpu,
                                              'samples': samples[cpu]}
                                             for cpu in xrange(len(samples))]},
                'symbolicationTable': dict((shortened[l], l) for l in shortened)
                }, 
              io, separators = (',', ':'))
