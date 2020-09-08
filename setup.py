'''
AMPT Monitor plugin for Zeek signature logs setup.

'''
from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    # Distribution package name should be "ampt-monitor-whatever"
    name='ampt-monitor-zeek',
    version='0.3.0',
    description='ampt-monitor plugin to read healthcheck alerts from the Zeek signature logs',
    long_description=long_description,
    url='https://github.com/nids-io/ampt-monitor-zeek',
    author='AMPT Project',
    author_email='ampt@nids.io',
    license='BSD',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: System :: Networking :: Monitoring',
    ],
    keywords='ampt, ampt-monitor, ampt-monitor-zeek, ampt-monitor-bro, zeek, bro, a passive network health monitoring tool',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[],
    # Entry points are key to the plugins system. Plugins are discovered and
    # loaded as drivers via setuptools entry points. Plugins should use the
    # specified namespace as the dict key, and the intended name of the plugin
    # as the entry point name.
    entry_points={
        # Namespace
        'ampt_monitor.plugin': [
            # Entry point name used as plugin name and used as a subsection
            # of [monitors] in ampt-manager configuration file
            'zeek = ampt_monitor_zeek.plugin:ZeekAMPTMonitor',
        ],
    },
)
