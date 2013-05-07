import re, subprocess, sys, threading

class CollectorThread(threading.Thread):
    def __init__(self, src, dst):
        threading.Thread.__init__(self)
        self.src = src
        self.dst = dst
        self.daemon = True
    def run(self):
        for thing in self.src:
            self.dst.append(thing)

class ReportParser:
    recordline_re = re.compile("(?P<cpu>[0-9]+) (?P<nsec>[0-9]+)"
                               + " 0x[0-9a-f]+ \[0x[0-9a-f]+\]: "
                               + "PERF_RECORD_(?P<name>[A-Z0-9_]+)"
                               + "(?P<thing>\(.*?\)|[^:]*): ?(?P<rest>[^ ].*)")
    mapinfo_re = re.compile("\[(?P<addr>0x[0-9a-f]+|0)\((?P<len>0x[0-9a-f]+)\)"
                            +" @ (?P<offset>[0-9]+|0x[0-9a-f]+)\]")
    frame_re = re.compile("\.\.\.\.\. *(?P<index>[0-9]+): (?P<pc>[0-9a-f]+)")

    def __init__(self, path, perfcmd = "perf", is_dump = False):
        self.needclose = False
        self.errbuf = []
        if is_dump:
            self.fh = open(path, "r")
            self.needclose = True
            self.proc = None
            self.errthread = None
        else:
            self.command = [perfcmd, "report", "-D", "-i", path]
            self.proc = subprocess.Popen(self.command,
                                         stdout = subprocess.PIPE,
                                         stderr = subprocess.PIPE)
            self.fh = self.proc.stdout
            self.errthread = CollectorThread(self.proc.stderr, self.errbuf)
            self.errthread.start()

    def finish(self):
        if self.needclose:
            self.fh.close()
        if self.errthread:
            self.errthread.join()
        if self.proc:
            self.proc.communicate()
            if self.proc.returncode != 0:
                print >>sys.stderr, "+ " + " ".join(self.command)
                if len(self.errbuf) > 0 and self.errbuf[-1][-1:] != "\n":
                    self.errbuf[-1] += "\n"
                for line in self.errbuf:
                    sys.stderr.write(line)
                print >>sys.stderr, ("perf exited with status %d"
                                     % self.proc.returncode)
                # Arguably this should raise....

    def __iter__(self):
        return self
    def next(self):
        for line in self.fh:
            header = ReportParser.recordline_re.match(line)
            if header:
                return self.parse_record(self.fh, header)
        self.finish()
        raise StopIteration

    def parse_record(self, fh, header):
        kind = header.group('name')
        out = { 'cpu': int(header.group('cpu')),
                'time': int(header.group('nsec')),
                'type': kind.lower() }
        if kind == 'MMAP':
            self.parse_mmap(header, out)
        elif kind == 'COMM':
            self.parse_comm(header, out)
        elif kind == 'FORK':
            self.parse_fork(header, out)
        elif kind == 'SAMPLE':
            self.parse_sample(header, out)
        else:
            print >>sys.stderr, ("Unhandled %s record" % kind)
        return out

    def parse_fork(self, header, out):
        out['ppid'], out['ptid'] = \
            map(int, header.group('rest').strip("()").split(":"))
        out['pid'], out['tid'] = \
            map(int, header.group('thing').strip("()").split(":"))

    def parse_comm(self, header, out):
        out['comm'], tid = header.group('rest').rsplit(":", 1)
        out['tid'] = int(tid)

    def parse_mmap(self, header, out):
        out['pid'], out['tid'] = map(int, header.group('thing').split("/"))
        mapinfo_str, out['filename'] = header.group('rest').split(": ")
        mapinfo = ReportParser.mapinfo_re.match(mapinfo_str)
        if not mapinfo:
            raise TypeError("MMAP without map info: %s" % mapinfo_str)
        out['addr'] = int(mapinfo.group('addr'), 16)
        out['len'] = int(mapinfo.group('len'), 16)
        out['offset'] = int(mapinfo.group('offset'), 16)
    
    def parse_sample(self, header, out):
        ptid, rest = header.group('rest').split(": ", 1)
        sample_ip, rest = rest.split(" ", 1)
        out['pid'], out['tid'] = map(int, ptid.split("/"))
        out['ip'] = int(sample_ip, 16)
        ips = []
        for line in self.fh:
            if line == "\n":
                break
            frame = ReportParser.frame_re.match(line)
            if frame:
                ips.append(int(frame.group('pc'), 16))
        out['ips'] = ips
