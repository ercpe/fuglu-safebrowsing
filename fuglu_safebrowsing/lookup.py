# -*- coding: utf-8 -*-
import re
import requests
from fuglu.shared import ScannerPlugin, DUNNO, string_to_actioncode

from fuglu_safebrowsing import VERSION
from fuglu_safebrowsing.cache import SimpleCache

DOMAINMAGIC_AVAILABLE = False
try:
    import domainmagic
    import domainmagic.extractor
    DOMAINMAGIC_AVAILABLE = True
except ImportError:
    pass


SAFEBROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class SafebrowsingLookupPlugin(ScannerPlugin):
    
    def __init__(self, *args, **kwargs):
        super(SafebrowsingLookupPlugin, self).__init__(*args, **kwargs)
        self.requiredvars = {
            'api-key': {
                'default': '',
                'description': 'API Key for Safebrowsing API',
                'confidential': True,
            },
            'action': {
                'default': '',
                'description': 'Default action to take on positive result',
            }
        }
        self.cache = SimpleCache()
        self.logger = self._logger()
    
    @property
    def api_key(self):
        if self.config.has_option(self.section, 'api-key'):
            return self.config.get(self.section, 'api-key')
        return None
    
    @property
    def default_action(self):
        return string_to_actioncode(self.config.get(self.section, 'action'))
    
    @property
    def threat_types(self):
        if self.config.has_option(self.section, 'threat-types'):
            config_values = self.config.get(self.section, 'threat-types')
            if config_values:
                return [x.strip().upper() for x in config_values.split()]
        
        return [
            "THREAT_TYPE_UNSPECIFIED", #	Unknown.
            "MALWARE", # Malware threat type.
            "SOCIAL_ENGINEERING", # Social engineering threat type.
            "UNWANTED_SOFTWARE", # Unwanted software threat type.
            "POTENTIALLY_HARMFUL_APPLICATION", # Potentially harmful application threat type.
        ]
    
    @property
    def threat_platforms(self):
        if self.config.has_option(self.section, 'threat-platforms'):
            config_values = self.config.get(self.section, 'threat-platforms')
            if config_values:
                return [x.strip().upper() for x in config_values.split()]

        return [
            "ANY_PLATFORM",  # Threat posed to at least one of the defined platforms.
        ]

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
    
    def examine(self, suspect):
        self.logger.info("Examine suspect %s", suspect)
        
        urls = self.extract_urls(suspect)
        if not urls:
            return DUNNO

        self.logger.info("Checking %s urls against Safebrowsing API", len(urls))
        result = self.check_safebrowsing(urls)

        if result:
            self.logger.info("Got %s results from Safebrowsing", len(result))
            return self.default_action

        return DUNNO

    def lint(self):
        x = super(SafebrowsingLookupPlugin, self).lint()

        if not DOMAINMAGIC_AVAILABLE:
            print("domainmagic lib or one of it's dependencies(dnspython/pygeoip) is not installed!")

        return x and DOMAINMAGIC_AVAILABLE

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
                    if "cacheDuration" not in match:
                        continue
                    
                    cache_duration = self.cache_duration_to_seconds(match['cacheDuration'])
                    if not cache_duration:
                        continue
                    
                    url = match['threat']['url']
                    self.cache.add(url, match, cache_duration)
                
                data['matches'].extend(cached_data)
            
            return data
        except:
            self.logger.exception("Request to Safebrowsing API failed")

    def cache_duration_to_seconds(self, duration_s):
        if not duration_s:
            return 0
        
        m = re.match("^(\d+)(?:\.\d+)s", duration_s, re.IGNORECASE)
        if m:
            return int(m.group(1))
        
        return 0

    def extract_urls(self, suspect):
        extractor = domainmagic.extractor.URIExtractor()
        textparts = " ".join(self.get_decoded_textparts(suspect.get_message_rep()))
        return extractor.extracturis(textparts)

    # copied from uriextract.py
    def get_decoded_textparts(self, messagerep):
        """Returns a list of all text contents"""
        parts = []
        for part in messagerep.walk():
            if part.is_multipart():
                continue
            filename = (part.get_filename(None) or "").lower()

            content_type = part.get_content_type()
        
            if content_type.startswith('text/') or filename.endswith(".txt") or \
                    filename.endswith(".html") or filename.endswith(".htm"):

                payload = part.get_payload(None, True)
                
                if 'html' in content_type or '.htm' in filename:
                    # remove newlines from html so we get uris spanning multiple lines
                    payload = payload.replace('\n', '').replace('\r', '')
            
                parts.append(payload)
        
            if content_type == 'multipart/alternative':
                try:
                    text = str(part.get_payload(None, True))
                    parts.append(text)
                except:
                    pass
    
        return parts
