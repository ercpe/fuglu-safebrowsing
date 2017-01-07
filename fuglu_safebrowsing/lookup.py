# -*- coding: utf-8 -*-
from fuglu.shared import ScannerPlugin


class SafebrowsingLookupPlugin(ScannerPlugin):
    
    def __init__(self, *args, **kwargs):
        super(SafebrowsingLookupPlugin, self).__init__(*args, **kwargs)
        self.requiredvars = {
            'api-key': {
                'default': '',
                'description': 'API Key for Safebrowsing API',
                'confidential': True,
            }
        }
