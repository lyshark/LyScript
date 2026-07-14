import setuptools
from distutils.core import  setup

packages = ['LyScript64']

setup(
    name='LyScript64',
    version='1.0.13',
    author='lyshark',
    description='A powerful x64dbg remote debugging module tools',
    author_email='me@lyshark.com',
    python_requires=">=3.6.0",
    license = "MIT Licence",
    packages=packages,
    include_package_data = True,
    platforms = "any"
    )
