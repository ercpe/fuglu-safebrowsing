# -*- coding: utf-8 -*-

import sys
import os

import pytest
from fuglu.shared import Suspect, DUNNO, DELETE
from mock import mock

from fuglu_safebrowsing import VERSION

if sys.version_info < (3, 0, 0):
    from ConfigParser import SafeConfigParser as ConfigParser
else:
    from configparser import ConfigParser

from fuglu_safebrowsing.lookup import SafebrowsingLookupPlugin


@pytest.fixture(name='config')
def config_fixture():
    cfg = ConfigParser()
    cfg.read([os.path.join(os.path.dirname(__file__), 'tests.cfg')])
    return cfg


@pytest.fixture(name='plugin')
def plugin_fixture():
    return SafebrowsingLookupPlugin(config_fixture())


@pytest.fixture(name='suspect')
def suspect_fixture():
    return Suspect("sender@example.com", "recipient@example.com",
                   os.path.join(os.path.dirname(__file__), '01-sample.eml'))


class TestLookup(object):
    def test_lint(self):
        plugin = SafebrowsingLookupPlugin(ConfigParser())
        assert not plugin.lint()
    
    def test_properties_no_config(self):
        cfg = ConfigParser()
        cfg.add_section('SafebrowsingLookupPlugin')
        
        plugin = SafebrowsingLookupPlugin(cfg)
        
        assert plugin.threat_platforms == ["ANY_PLATFORM"]
        assert plugin.threat_types == [
            "THREAT_TYPE_UNSPECIFIED",
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
        ]
        assert plugin.request_timeout == 10
    
    def test_properties_config(self, plugin):
        assert plugin.threat_platforms == ["ALL_PLATFORMS"]
        assert plugin.threat_types == [
            "MALWARE",
            "SOCIAL_ENGINEERING",
        ]
        assert plugin.request_timeout == 1
    
    def test_requests_kwargs(self):
        cfg = ConfigParser()
        cfg.add_section('SafebrowsingLookupPlugin')
        
        plugin = SafebrowsingLookupPlugin(cfg)
        
        assert plugin.requests_kwargs == {
            'headers': {
                'User-Agent': 'fuglu-safebrowsing %s' % VERSION
            },
            'timeout': 10.0
        }
    
    def test_examine_no_urls(self, plugin, suspect):
        plugin.check_safebrowsing = mock.MagicMock()
        plugin.extract_urls = mock.MagicMock(return_value=[])
        
        assert plugin.examine(suspect) == DUNNO
        plugin.check_safebrowsing.assert_not_called()
    
    @mock.patch("fuglu_safebrowsing.lookup.requests")
    def test_check_safebrowsing_no_apikey(self, requests_mock):
        cfg = ConfigParser()
        cfg.add_section('SafebrowsingLookupPlugin')
        
        plugin = SafebrowsingLookupPlugin(cfg)
        
        assert not plugin.check_safebrowsing(["http://example.com"])
        requests_mock.post.assert_not_called()
    
    @mock.patch("fuglu_safebrowsing.lookup.requests")
    def test_check_safebrowsing(self, requests_mock, plugin):
        response_mock = mock.MagicMock()
        response_mock.json = mock.MagicMock(return_value=[])
        requests_mock.post = mock.MagicMock(return_value=response_mock)
        
        assert plugin.check_safebrowsing(["http://example.com"]) == []
        requests_mock.post.assert_called_with(
            'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=some-api-key', json={
                'client': {
                    'clientId': 'fuglu-safebrowsing',
                    'clientVersion': VERSION
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ALL_PLATFORMS"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "http://example.com"}]
                }
            }, headers={
                'User-Agent': 'fuglu-safebrowsing %s' % VERSION
            }, timeout=1.0
        )
    
    @mock.patch("fuglu_safebrowsing.lookup.requests")
    def test_check_safebrowsing_no_result(self, requests_mock, plugin, suspect):
        response_mock = mock.MagicMock()
        response_mock.json = mock.MagicMock(return_value=[])
        requests_mock.post = mock.MagicMock(return_value=response_mock)
        
        plugin.extract_urls = mock.MagicMock(return_value=["http://example.com"])
        
        assert plugin.examine(suspect) == DUNNO
    
    @mock.patch("fuglu_safebrowsing.lookup.requests")
    def test_check_safebrowsing_positive_result(self, requests_mock, plugin, suspect):
        response_mock = mock.MagicMock()
        response_mock.json = mock.MagicMock(return_value={
            "matches": [{
                "threatType": "MALWARE",
                "platformType": "WINDOWS",
                "threatEntryType": "URL",
                "threat": {"url": "http://example.com/"},
                "threatEntryMetadata": {
                    "entries": [{
                        "key": "malware_threat_type",
                        "value": "landing"
                    }]
                },
                "cacheDuration": "300.000s"
            }]
        })
        requests_mock.post = mock.MagicMock(return_value=response_mock)
        
        plugin.extract_urls = mock.MagicMock(return_value=["http://example.com"])
        
        assert plugin.examine(suspect) == DELETE

    @mock.patch("fuglu_safebrowsing.lookup.requests")
    def test_check_safebrowsing_cached(self, requests_mock, plugin, suspect):
        url = "http://example.com"
        data = {
            "threatType": "MALWARE",
            "platformType": "WINDOWS",
            "threatEntryType": "URL",
            "threat": {"url": url},
            "threatEntryMetadata": {
                "entries": [{
                    "key": "malware_threat_type",
                    "value": "landing"
                }]
            },
            "cacheDuration": "300.000s"
        }
        
        plugin.cache.add(url, data, 300)

        assert plugin.check_safebrowsing([url]) == {
            'matches': [data]
        }
        requests_mock.post.assert_not_called()

    @mock.patch("fuglu_safebrowsing.lookup.requests")
    def test_check_safebrowsing_positive_result_cache(self, requests_mock, plugin, suspect):
        url = "http://example.com"

        data = {
                "threatType": "MALWARE",
                "platformType": "WINDOWS",
                "threatEntryType": "URL",
                "threat": {"url": url},
                "threatEntryMetadata": {
                    "entries": [{
                        "key": "malware_threat_type",
                        "value": "landing"
                    }]
                },
                "cacheDuration": "300.000s"
            }

        response_mock = mock.MagicMock()
        response_mock.json = mock.MagicMock(return_value={
            "matches": [data]
        })
        requests_mock.post = mock.MagicMock(return_value=response_mock)
    
        assert plugin.check_safebrowsing([url]) == {
            'matches': [data]
        }
        requests_mock.post.assert_called()

        # requery again to test that caches is used
        assert plugin.check_safebrowsing([url]) == {
            'matches': [data]
        }
        requests_mock.post.assert_called_once()

    def test_extract_urls(self, plugin, suspect):
        assert plugin.extract_urls(suspect) == [
            "http://diechatburg.de/media/editors/tinymce/plugins/advlist/"
        ]

    def test_cache_duration_to_seconds(self, plugin):
        assert plugin.cache_duration_to_seconds(None) == 0
        assert plugin.cache_duration_to_seconds("") == 0
        assert plugin.cache_duration_to_seconds("123") == 0
        assert plugin.cache_duration_to_seconds("123.0") == 0

        assert plugin.cache_duration_to_seconds("300.0s") == 300
        assert plugin.cache_duration_to_seconds("300.123s") == 300
