# coding: UTF-8

class ObjectSet(object):
    """ObjectSet(iterable) --> ObjectSet object

    Build a set of arbitrary objects.
    """
    def __init__(self, iterable=None):
        self._dict = {}
        if iterable:
            for elem in iterable:
                self.add(elem)

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        return self._dict.itervalues()

    def __repr__(self):
        return 'ObjectSet(' + repr(self._dict.values()) + ')'

    def __contains__(self, elem):
        return id(elem) in self._dict

    def union(self, *others):
        new_set = self.copy()
        new_set.update(*others)
        return new_set
    __or__ = union

    def copy(self):
        new_set = ObjectSet()
        new_set._dict = self._dict.copy()
        return new_set

    def update(self, *others):
        for other in others:
            for elem in other:
                self.add(elem)
        return self
    __ior__ = update

    def difference_update(self, *others):
        for other in others:
            for elem in other:
                self.discard(elem)
        return self
    __isub__ = difference_update

    def add(self, elem):
        self._dict[id(elem)] = elem

    def remove(self, elem):
        del self._dict[id(elem)]

    def discard(self, elem):
        if elem in self:
            self.remove(elem)

    def pop(self):
        _, elem = self._dict.popitem()
        return elem

    def clear(self):
        self._dict.clear()

class ObjectDict(object):
    """ObjectDict() --> ObjectDict object

    Build a dictionary whose key can be any object.
    """
    def __init__(self):
        self._keys = {}
        self._values = {}

    def __len__(self):
        return len(self._keys)

    def __getitem__(self, key):
        return self._values[id(key)]

    def __setitem__(self, key, value):
        self._keys[id(key)] = key
        self._values[id(key)] = value

    def __delitem__(self, key):
        del self._keys[id(key)]
        del self._values[id(key)]

    def __contains__(self, key):
        return id(key) in self._keys
    
    def __iter__(self):
        return self._keys.itervalues()

    def clear(self):
        self._keys.clear()
        self._values.clear()

    def get(self, key, default=None):
        return self._values.get(id(key), default)

    def has_key(self, key):
        return id(key) in self._keys

    def items(self):
        return list(self.iteritems())

    def keys(self):
        return self._keys.values()

    def values(self):
        return self._values.values()

    def iteritems(self):
        for k in self._keys.iterkeys():
            yield self._keys[k], self._values[k]

    def iterkeys(self):
        return self._keys.itervalues()

    def itervalues(self):
        return self._values.itervalues()

    def popitem(self):
        key_id, key = self._keys.popitem()
        value = self._values.pop(key_id)
        return key, value

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

def flatten(obj):
    try:
        for subobj in obj:
            for item in flatten(subobj):
                if not hasattr(item, 'get_rlist'):
                    print repr(item), repr(subobj), repr(obj)
                yield item
    except TypeError:
        yield obj

def get_select_list(m, *args):
    mlist = []
    mdict = {}
    for conn in flatten(args):
        flist = getattr(conn, m)()
        if not flist:
            continue
        mlist += flist
        for fno in flist:
            mdict[fno] = conn
    return mlist, mdict

def import_backend(config):
    fromlist = ['ServerBackend', 'ClientBackend']
    package = 'backend.' + config['backend']['type']
    return __import__(package, fromlist=fromlist)

def import_frontend(config):
    fromlist = ['FrontendServer']
    package = 'frontend.' + config['frontend']['type']
    package = __import__(package, fromlist=fromlist)
    FrontendServer = package.FrontendServer
    return lambda: FrontendServer(**config['frontend'])
