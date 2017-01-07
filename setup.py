#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

from fuglu_safebrowsing import VERSION

setup(
    name='fuglu-safebrowsing',
    version=VERSION,
    description='Fuglu plugin for the Google Safebrowsing API',
    author='Johann Schmitz',
    author_email='johann@j-schmitz.net',
    url='https://code.not-your-server.de/fuglu-safebrowsing.git',
    download_url='https://code.not-your-server.de/fuglu-safebrowsing.git/tags/',
    packages=find_packages(exclude=('tests', )),
    include_package_data=True,
    zip_safe=False,
    license='GPL-3',
)
