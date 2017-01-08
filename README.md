# fuglu-safebrowsing

`fuglu-safebrowsing` is a [Fuglu](http://fuglu.org/) plugin for [Google's Safebrowsing API](https://developers.google.com/safe-browsing/v4/).

For now, only the Lookup API is implemented (Update API coming soon). Please see Google's documentation about the differences before enabling this plugin in fuglu.
 
You will need an API key to use this plugin. Please follow the steps at https://developers.google.com/safe-browsing/v4/get-started to get one. 
 

## Configuration

After installation, add `fuglu_safebrowsing.lookup.SafebrowsingLookupPlugin` to your configuration:
 
	[PluginAlias]
	safebrowsing=fuglu_safebrowsing.lookup.SafebrowsingLookupPlugin
	
	[main]
	plugins=...,safebrowsing


and add a section for the plugin:

	[SafebrowsingLookupPlugin]
	api-key = yourapikey
	
	# action to take on a positive response (e.g. DELETE, REJECT)
	action=

	# optional: request timeout (defaults to 10 seconds)
	# timeout = 10
	
	# optional: whitespace seperated list of threat types to query for (defaults to all)
	# see https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType
	# threat-types = THREAT_TYPE_UNSPECIFIED MALWARE SOCIAL_ENGINEERING UNWANTED_SOFTWARE POTENTIALLY_HARMFUL_APPLICATION

	# optional: whitespace separated list of threat platforms to query for (defaults to ANY_PLATFORM)
	# see https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
	threat-platforms = ANY_PLATFORM

## License

See LICENSE.txt

