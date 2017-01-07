# -*- coding: utf-8 -*-

import sys
if sys.version_info < (3, 0, 0):
    from ConfigParser import SafeConfigParser as ConfigParser
else:
    from configparser import ConfigParser

from fuglu_safebrowsing.lookup import SafebrowsingLookupPlugin


class TestLookup(object):
    
    def test_lint(self):
        plugin = SafebrowsingLookupPlugin(ConfigParser())
        assert not plugin.lint()
