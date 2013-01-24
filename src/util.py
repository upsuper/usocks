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

    def __contains__(self, elem):
        return id(elem) in self._dict

    def add(self, elem):
        self._dict[id(elem)] = elem

    def remove(self, elem):
        del self._dict[id(elem)]

    def discard(self, elem):
        if elem in self:
            del self._dict[id(elem)]

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
        return ((self._keys[k], self._values[k])
                for k in self._keys.iterkeys())

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