# -*- coding: utf-8 -*-
import datetime


class SimpleCache(object):
    
    def __init__(self):
        self._data = {}
    
    def get(self, url):
        if url not in self._data:
            return None
        
        max_datetime, data = self._data[url]
        
        if max_datetime <= datetime.datetime.utcnow():
            del self._data[url]
            return None
        
        return data

    def get_many(self, urls):
        def _inner():
            for u in urls:
                x = self.get(u)
                if x:
                    yield x
        
        return list(_inner())
    
    def add(self, url, data, timeout):
        dt = datetime.datetime.utcnow() + datetime.timedelta(seconds=timeout)
        self._data[url] = (dt, data)
