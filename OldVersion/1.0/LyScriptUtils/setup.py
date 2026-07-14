import setuptools
from distutils.core import setup

packages = ['LyScriptUtils']

setup(
    name='LyScriptUtils',
    version='1.0.1',
    author='lyshark',
    description='A powerful x64dbg remote debugging module tools',
    author_email='me@lyshark.com',
    python_requires=">=3.6.0",
    license = "MIT Licence",
    packages=packages,
    include_package_data = True,
    platforms = "any"
    )
