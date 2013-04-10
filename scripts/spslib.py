import json, re

def load(path):
    with open(path) as fh:
        return SPS.load(fh)

class SPS:
    def __init__(self, samples):
        self.samples = samples

    @classmethod
    def load(self, fh):
        prof = json.load(fh)
        symtab = prof.get('symbolicationTable', None)
        allSamples = []
        for thread in prof['profileJSON']['threads']:
            samples = thread['samples'][:]
            if symtab:
                for sample in samples:
                    # FIXME: deal with dict frames
                    sample['frames'] = [symtab.get(name, name) 
                                        for name in sample['frames']]
            if len(samples) == 0:
                continue
            elif len(samples) == 1:
                samples[0]['duration'] = 0
            else:
                samples[0]['duration'] = \
                    samples[1]['time'] - samples[0]['time']
                samples[-1]['duration'] = \
                    samples[-1]['time'] - samples[-2]['time']
            for i in xrange(1, len(samples) - 1):
                samples[i]['duration'] = \
                    (samples[i+1]['time'] - samples[i-1]['time']) / 2
            allSamples += samples
        return self(allSamples)

    def __len__(self):
        return len(self.samples)

    def time(self):
        return sum(sample['duration'] for sample in self.samples)

    def grep(self, *search):
        rs = map(re.compile, search)
        return self.__class__([sample
                               for sample in self.samples
                               if all(any(r.search(frame)
                                          for frame in sample['frames'])
                                      for r in rs)])
    def grep_v(self, *unsearch):
        rs = map(re.compile, unsearch)
        return self.__class__([sample
                               for sample in self.samples
                               if not all(any(r.search(frame)
                                              for frame in sample['frames']) 
                                          for r in rs)])

    def group(self, *search):
        rs = map(re.compile, search)
        things = [[]]
        for sample in self.samples:
            if sample['frames'][2:3] == ["Corrupt Stack"]:
                continue
            if all(any(r.search(frame)
                       for frame in sample['frames'])
                   for r in rs):
                things[-1].append(sample)
            else:
                if things[-1]:
                    things.append([])
        if not things[-1]:
            things[-1:] = []
        return map(self.__class__, things)

    def mainthread(self, pname = "b2g"):
        acc = []
        pre = re.compile("%s \(in pid (?P<pid>\d+)\)" % pname)
        for sample in self.samples:
            fs = sample['frames']
            if len(fs) < 2:
                continue
            m = pre.match(fs[0])
            if m and fs[1] == "%s (in tid %s)" % (pname, m.group('pid')):
                acc.append(sample)
        return self.__class__(acc)

    def paints(self):
        return self.groups("nsRefreshDriver::Notify", "PresShell::Paint")
    
