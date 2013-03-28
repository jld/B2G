import json, os, sys, re
from datetime import datetime

recordline_re = re.compile("(?P<cpu>[0-9]+) (?P<nsec>[0-9]+) 0x[0-9a-f]+ "
                           +"\[0x[0-9a-f]+\]: PERF_RECORD_(?P<name>[A-Z0-9_]+)"
                           +"(?P<thing>\(.*?\)|[^:]*): ?(?P<rest>[^ ].*)")
mapinfo_re = re.compile("\[(?P<addr>0x[0-9a-f]+)\((?P<len>0x[0-9a-f]+)\)"
                        +" @ (?P<offset>[0-9]+|0x[0-9a-f]+)\]")
frame_re = re.compile("\.\.\.\.\. *[0-9]+: (?P<pc>[0-9a-f]+)")



mmaps = {} # pid => "libs" array
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
        if pid not in mmaps:
            mmaps[pid] = []
        start32 = addr & 0xFFFFFFFF
        end32 = (addr + maplen) & 0xFFFFFFFF
        mmaps[pid].append({ 'name': name,
                            'start': min(start32, end32),
                            'end': max(start32, end32),
                            'offset': offset })
    elif kind == 'COMM':
        (name, tid) = header.group('rest').rsplit(":", 1)
        tid = int(tid)
        names[tid] = name
        # FIXME: how do we distinguish an exec from a thread name change?
    elif kind == 'FORK':
        ppid, ptid = map(int, header.group('rest').strip("()").split(":"))
        cpid, ctid = map(int, header.group('thing').strip("()").split(":"))
        note_thread(cpid, ctid)
        if ppid in mmaps:
            mmaps[cpid] = mmaps[ppid][:]
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
                pc32 = frame.group('pc')[-8:]
                frames.append({'location': "0x" + pc32})
        frames.append({ 'location': "%s (in tid %d)" \
                            % (names.get(tid, "???"), tid) })
        frames.append({ 'location': "%s (in pid %d)" \
                            % (names.get(maintid[pid], "???"), pid) })
        frames.reverse()
        while cpu >= len(samples):
            samples.append([])
        samples[cpu].append({ 'time': msec,
                              'space': str(pid),
                              'frames': frames })
    else:
        print >>sys.stderr, ("Unhandled %s record" % kind)


timestamp = datetime.now().strftime("%H%M")
with open("perf_%s.txt" % timestamp, "w") as io:
    libs = mmaps[-1]
    for pid in mmaps:
        if pid >= 0:
            libs += [dict(mmap, space=str(pid))
                     for mmap in mmaps[pid]
                     # Drop kernel mappings; kallsyms has them.
                     if mmap['name'][0] == "/"]
    json.dump({ 'libs': json.dumps(libs),
                'threads': [{ 'name': "CPU %d" % cpu,
                              'samples': samples[cpu]}
                            for cpu in xrange(len(samples))]},
              io)
