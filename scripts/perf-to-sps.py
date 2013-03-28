import json, os, sys, re
from datetime import datetime

recordline_re = re.compile("(?P<cpu>[0-9]+) (?P<nsec>[0-9]+) 0x[0-9a-f]+ "
                           +"\[0x[0-9a-f]+\]: PERF_RECORD_(?P<name>[A-Z0-9_]+)"
                           +"(?P<thing>\(.*?\)|[^:]*): ?(?P<rest>[^ ].*)")
mapinfo_re = re.compile("\[(?P<addr>0x[0-9a-f]+)\((?P<len>0x[0-9a-f]+)\)"
                        +" @ (?P<offset>[0-9]+|0x[0-9a-f]+)\]")
frame_re = re.compile("\.\.\.\.\. *[0-9]+: (?P<pc>[0-9a-f]+)")

class AddrSpace:
    mask = 0xFFFFFFFF
    bucket = 1 << 24
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


spaces = {} # pid => AddrSpace
pids = {}  # tid => pid
maintid = {} # pid => tid
names = {0: "swapper"} # tid => string
samples = [] # cpu => sample array

def note_thread(pid, tid):
    pids[tid] = pid
    if pid not in maintid or maintid[pid] > tid:
        maintid[pid] = tid

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
        if pid not in spaces:
            spaces[pid] = AddrSpace()
        spaces[pid].mmap(addr, addr + maplen, offset, name)
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
                sym = (pid in spaces and spaces[pid].lookup(pc)) \
                    or spaces[-1].lookup(pc)
                if sym:
                    frames.append({'location': "%s:%#x" % sym})
                else:
                    frames.append({'location': "%#x" % pc})
        frames.append({ 'location': "%s (in tid %d)" \
                            % (names.get(tid, "???"), tid) })
        frames.append({ 'location': "%s (in pid %d)" \
                            % (names.get(maintid[pid], "???"), pid) })
        frames.reverse()
        while cpu >= len(samples):
            samples.append([])
        samples[cpu].append({ 'time': msec,
                              'frames': frames })
    else:
        print >>sys.stderr, ("Unhandled %s record" % kind)


timestamp = datetime.now().strftime("%H%M")
with open("perf_%s.txt" % timestamp, "w") as io:
    json.dump({ 'threads': [{ 'name': "CPU %d" % cpu,
                              'samples': samples[cpu]}
                            for cpu in xrange(len(samples))]},
              io)
