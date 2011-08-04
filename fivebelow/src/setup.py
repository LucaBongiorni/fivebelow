# setup.py

from distutils.core import setup
import py2exe, sys, os

sys.argv.append('py2exe')

setup(
      console=[{'script': 'fivebelow.py', 'icon_resources': [(0, 'fivebelow.ico')]}],
      options = {'py2exe': {'bundle_files': 1}},
      data_files=[ ( "config",["config/config.xml"] ),
                  ( ".",["README.txt"] ) ],
      zipfile = None,
      )