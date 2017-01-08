# -*- coding: utf-8 -*-
import requests

from fuglu_safebrowsing import VERSION
from fuglu_safebrowsing.base import BaseSafebrowsingPlugin
from fuglu_safebrowsing.cache import SimpleCache


SAFEBROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class SafebrowsingLookupPlugin(BaseSafebrowsingPlugin):
    
    def __init__(self, *args, **kwargs):
        super(SafebrowsingLookupPlugin, self).__init__(*args, **kwargs)
        self.cache = SimpleCache()
        self.logger = self._logger()
    
    @property
    def requests_kwargs(self):
        return {
            'headers': {
                'User-Agent': 'fuglu-safebrowsing %s' % VERSION
            },
            'timeout': float(self.request_timeout)
        }
    
    @property
    def request_timeout(self):
        if self.config.has_option(self.section, 'timeout'):
            return self.config.getint(self.section, 'timeout')
        return 10
    
    def check_safebrowsing(self, urls):
        if not (self.api_key and urls):
            return

        cached_data = self.cache.get_many(urls)
        self.logger.info("Found %s cached results", len(cached_data))
        cached_urls = [x['threat']['url'] for x in cached_data]

        request_data = {
            'client': {
                'clientId': 'fuglu-safebrowsing',
                'clientVersion': VERSION
            },
            "threatInfo": {
                "threatTypes": self.threat_types,
                "platformTypes": self.threat_platforms,
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls if u not in cached_urls]
            }
        }
        
        try:
            data = {
                'matches': []
            }
            
            if request_data['threatInfo']['threatEntries']:
                response = requests.post(SAFEBROWSING_API_URL + '?key=%s' % self.api_key,
                                         json=request_data,
                                         **self.requests_kwargs)
                response.raise_for_status()
                
                data = response.json()

            if data and 'matches' in data:
                for match in data['matches']:
                    cache_duration = self.cache_duration_to_seconds(match.get('cacheDuration', ''))
                    url = match['threat']['url']
                    self.cache.add(url, match, cache_duration)
                
                data['matches'].extend(cached_data)
            
            return data
        except:
            self.logger.exception("Request to Safebrowsing API failed")
