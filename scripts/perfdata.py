import struct, sys

PERF_SAMPLE_IP				= 1 << 0
PERF_SAMPLE_TID				= 1 << 1
PERF_SAMPLE_TIME			= 1 << 2
PERF_SAMPLE_ADDR			= 1 << 3
PERF_SAMPLE_READ			= 1 << 4
PERF_SAMPLE_CALLCHAIN			= 1 << 5
PERF_SAMPLE_ID				= 1 << 6
PERF_SAMPLE_CPU				= 1 << 7
PERF_SAMPLE_PERIOD			= 1 << 8
PERF_SAMPLE_STREAM_ID			= 1 << 9
PERF_SAMPLE_RAW				= 1 << 10

PERF_SAMPLE_ID_ALL_MASK = \
    PERF_SAMPLE_TID    | \
    PERF_SAMPLE_TIME   | \
    PERF_SAMPLE_ID     | \
    PERF_SAMPLE_CPU    | \
    PERF_SAMPLE_STREAM_ID

PERF_RECORD_MISC_CPUMODE_MASK		= 7 << 0
PERF_RECORD_MISC_CPUMODE_UNKNOWN	= 0 << 0
PERF_RECORD_MISC_KERNEL			= 1 << 0
PERF_RECORD_MISC_USER			= 2 << 0
PERF_RECORD_MISC_HYPERVISOR		= 3 << 0
PERF_RECORD_MISC_GUEST_KERNEL		= 4 << 0
PERF_RECORD_MISC_GUEST_USER		= 5 << 0

PERF_RECORD_MMAP			= 1
PERF_RECORD_LOST			= 2
PERF_RECORD_COMM			= 3
PERF_RECORD_EXIT			= 4
PERF_RECORD_THROTTLE			= 5
PERF_RECORD_UNTHROTTLE			= 6
PERF_RECORD_FORK			= 7
PERF_RECORD_READ			= 8
PERF_RECORD_SAMPLE			= 9

def UnpackNone():
    return UnpackProduct()

class UnpackProduct:
    def __init__(self, *fields):
        flattened = []
        for f in fields:
            if isinstance(f, UnpackProduct):
                flattened += f.fields
            else:
                flattened.append(f)
        self.fields = flattened
    def unpack(self, buf, out, offset = 0):
        for f in self.fields:
            offset = f.unpack(buf, out, offset)
        return offset

class UnpackU64Array:
    def __init__(self, endian, key):
        self.key = key
        self.q = endian + "Q"
    def unpack(self, buf, out, offset = 0):
        nr = struct.unpack_from(self.q, buf, offset)[0]
        u64s = []
        # Is this less bad than str'ing nr?
        for i in xrange(nr):
            u64s.append(struct.unpack_from(self.q, buf,
                                           offset + 8 * (i + 1))[0])
        out[self.key] = u64s
        return offset + 8 * (nr + 1)

class UnpackPaddedString:
    def __init__(self, key):
        self.key = key
    def unpack(self, buf, out, offset = 0):
        nil = buf.find("\0", offset)
        out[self.key] = buf[offset:nil]
        # 1 for '\0' + 7 for roundup = 8
        return (nil + 8) & ~7

class UnpackStruct:
    def __init__(self, endian, keys, fmt):
        self.keys = keys
        self.fmt = endian + fmt
        self.size = struct.calcsize(self.fmt)
    def unpack(self, buf, out, offset = 0):
        # print >>sys.stderr, ("fmt=%s off=%d len=%d" % (self.fmt, offset, len(buf)))
        out.update(zip(self.keys, struct.unpack_from(self.fmt, buf, offset)))
        return offset + self.size

def UnpackSample(endian, sample_type):
    keys = \
        (['ip'] if sample_type & PERF_SAMPLE_IP else []) + \
        (['pid','tid'] if sample_type & PERF_SAMPLE_TID else []) + \
        (['time'] if sample_type & PERF_SAMPLE_TIME else []) + \
        (['addr'] if sample_type & PERF_SAMPLE_ADDR else []) + \
        (['id'] if sample_type & PERF_SAMPLE_ID else []) + \
        (['stream_id'] if sample_type & PERF_SAMPLE_STREAM_ID else []) + \
        (['cpu'] if sample_type & PERF_SAMPLE_CPU else []) + \
        (['period'] if sample_type & PERF_SAMPLE_PERIOD else [])
    fmt = \
        ("Q" if sample_type & PERF_SAMPLE_IP else "") + \
        ("LL" if sample_type & PERF_SAMPLE_TID else "") + \
        ("Q" if sample_type & PERF_SAMPLE_TIME else "") + \
        ("Q" if sample_type & PERF_SAMPLE_ADDR else "") + \
        ("Q" if sample_type & PERF_SAMPLE_ID else "") + \
        ("Q" if sample_type & PERF_SAMPLE_STREAM_ID else "") + \
        ("L4x" if sample_type & PERF_SAMPLE_CPU else "") + \
        ("Q" if sample_type & PERF_SAMPLE_PERIOD else "")
    thing = UnpackStruct(endian, keys, fmt)
    if sample_type & PERF_SAMPLE_CALLCHAIN:
        thing = UnpackProduct(thing, UnpackU64Array(endian, 'ips'))
    return thing

def perf_record_unpackers(endian, sample_type, id_all = True):
        if id_all:
            unpack_id_all = \
                UnpackSample(endian, sample_type & PERF_SAMPLE_ID_ALL_MASK)
        else:
            unpack_id_all = UnpackNone()
        return [
            ('mmap',
             UnpackProduct(UnpackStruct(endian, ['pid', 'tid', 'addr', 'len',
                                                 'offset'], "LLQQQ"),
                           UnpackPaddedString('filename'),
                           unpack_id_all)),
            ('lost',
             UnpackProduct(UnpackStruct(endian, ['id', 'lost'], "QQ"),
                           unpack_id_all)),
            ('comm',
             UnpackProduct(UnpackStruct(endian, ['pid', 'tid'], "LL"),
                           UnpackPaddedString('comm'),
                           unpack_id_all)),
            ('exit',
             UnpackProduct(
                    UnpackStruct(endian, ['pid', 'ppid', 'tid', 'ptid',
                                          'time'], "LLLLQ"),
                    unpack_id_all)),
            ('throttle',
             UnpackProduct(
                    UnpackStruct(endian, ['time', 'id', 'stream_id'], "QQQ"),
                    unpack_id_all)),
            ('unthrottle',
             UnpackProduct(
                    UnpackStruct(endian, ['time', 'id', 'stream_id'], "QQQ"),
                    unpack_id_all)),
            ('fork',
             UnpackProduct(
                    UnpackStruct(endian, ['pid', 'ppid', 'tid', 'ptid',
                                          'time'], "LLLLQ"),
                    unpack_id_all)),
            ('read', # Unimplemnted
             None),
            ('sample',
             UnpackSample(endian, sample_type)),
            ]

class PerfRecordReader:
    def __init__(self, endian, sample_type, fh, id_all = True):
        self.fh = fh
        self.header_fmt = endian + "LHH"
        self.unpack_bodies = perf_record_unpackers(endian, sample_type, id_all)
    def __iter__(self):
        return self
    def next(self):
        header = self.fh.read(8)
        if not header:
            raise StopIteration
        (rectype, misc, size) = struct.unpack(self.header_fmt, header)
        body = self.fh.read(size - 8)
        if rectype == 0 or rectype > len(self.unpack_bodies):
            raise TypeError("unknown perf record type %d" % rectype)
        typestr, unpack_body = self.unpack_bodies[rectype - 1]
        rec = { 'misc': misc, 'type': typestr }
        unpack_body.unpack(body, rec)
        return rec

def MiniPerfReader(fh):
    header = fh.read(24)
    magic = header[0:8]
    if magic == "MiniPerf":
        endian = "<"
    elif magic == "frePiniM":
        endian = ">"
    else:
        return None
    if header[8:16] != "\0" * 8:
        raise TypeError("MiniPerf file is from the future?")
    sample_type = struct.unpack(endian + "Q", header[16:24])[0]
    return PerfRecordReader(endian, sample_type, fh)
