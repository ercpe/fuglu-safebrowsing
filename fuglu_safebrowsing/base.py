# -*- coding: utf-8 -*-

import re
from fuglu.shared import ScannerPlugin, DUNNO, string_to_actioncode

DOMAINMAGIC_AVAILABLE = False
try:
    import domainmagic
    import domainmagic.extractor
    DOMAINMAGIC_AVAILABLE = True
except ImportError:
    pass


class BaseSafebrowsingPlugin(ScannerPlugin):
    def __init__(self, *args, **kwargs):
        super(BaseSafebrowsingPlugin, self).__init__(*args, **kwargs)
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
            "THREAT_TYPE_UNSPECIFIED",  # Unknown.
            "MALWARE",  # Malware threat type.
            "SOCIAL_ENGINEERING",  # Social engineering threat type.
            "UNWANTED_SOFTWARE",  # Unwanted software threat type.
            "POTENTIALLY_HARMFUL_APPLICATION",  # Potentially harmful application threat type.
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
        x = super(BaseSafebrowsingPlugin, self).lint()
        
        if not DOMAINMAGIC_AVAILABLE:
            print("domainmagic lib or one of it's dependencies(dnspython/pygeoip) is not installed!")
        
        return x and DOMAINMAGIC_AVAILABLE
    
    def check_safebrowsing(self, urls):
        raise NotImplementedError()
    
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
