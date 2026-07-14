import setuptools
from distutils.core import  setup

packages = ['LyScriptTools32']

setup(
    name='LyScriptTools32',
    version='1.0.6',
    author='lyshark',
    description='A powerful x64dbg remote debugging module tools',
    author_email='me@lyshark.com',
    python_requires=">=3.6.0",
    license = "MIT Licence",
    packages=packages,
    include_package_data = True,
    platforms = "any"
    )
