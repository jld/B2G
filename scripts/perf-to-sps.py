import json, os, sys, re

recordline_re = re.compile("(?P<cpu>[0-9]+) (?P<nsec>[0-9]+) 0x[0-9a-f]+ "
                           +"\[0x[0-9a-f]+\]: PERF_RECORD_(?P<name>[A-Z0-9_]+)"
                           +"(?P<thing>\(.*?\)|[^:]*): ?(?P<rest>[^ ].*)")
mapinfo_re = re.compile("\[(?P<addr>0x[0-9a-f]+)\((?P<len>0x[0-9a-f]+)\)"
                        +" @ (?P<offset>[0-9]+|0x[0-9a-f]+)\]")
frame_re = re.compile("\.\.\.\.\. *[0-9]+: (?P<pc>[0-9a-f]+)")



mmaps = {} # pid => "libs" array
pids = {}  # tid => pid
names = {0: "swapper"} # tid => string
samples = {} # tid => sample array

for line in sys.stdin:
    header = recordline_re.match(line)
    if not header:
        continue
    kind = header.group('name')
    if kind == 'MMAP':
        pid, tid = map(int, header.group('thing').split("/"))
        mapinfo_str, name = header.group('rest').split(": ")
        if name[:2] == "//":
            continue
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
        pids[ctid] = cpid
        mmaps[cpid] = mmaps[ppid][:]
        names[ctid] = names[ptid]
    elif kind == 'EXIT':
        # Not handling this yet...
        pass
    elif kind == 'SAMPLE':
        pid, tid = map(int, header.group('rest').split(": ")[0].split("/"))
        if tid not in pids:
            pids[tid] = pid
        frames = []
        for line in sys.stdin:
            if line == "\n":
                break
            frame = frame_re.match(line)
            if frame:
                pc32 = frame.group('pc')[-8:]
                frames.append({'location': "0x" + pc32})
        frames.reverse()
        if tid not in samples:
            samples[tid] = []
        samples[tid].append({ 'name': names[tid], # ???
                              'time': int(header.group('nsec')) / 1e6,
                              'frames': frames })
    else:
        print >>sys.stderr, ("Unhandled %s record" % kind)

for tid in samples:
    # FIXME: timestamp
    pid = pids[tid]
    safename = re.sub("/", ":", names[tid])
    fname = "_".join(["perf", str(pid), str(tid), safename]) + ".txt"
    with open(fname, "w") as io:
        json.dump({ 'libs': json.dumps(mmaps.get(pid, []) + mmaps[-1]),
                    'threads': [{'samples': samples[tid]}] },
                  io)

                    
    
