from setuptools import setup, find_packages
import sys, os

version = '2.0'

setup(name='BeautifulCleaner',
      version=version,
      description="A port of lxml.html.clean.Cleaner to the BeautifulSoup api",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='sanitize clean html beautifulsoup',
      author='Jon Rosebaugh',
      author_email='',
      url='',
      license='',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=["BeautifulSoup>=3.0.5"
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
