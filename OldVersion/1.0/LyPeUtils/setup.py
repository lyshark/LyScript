import setuptools
from distutils.core import  setup

packages = ['LyPeUtils']

setup(

    install_requires=["pefile<=2022.5.30"],
    name='LyPeUtils',
    version='1.0.0',
    author='lyshark',
    description='A powerful x64dbg remote debugging module tools',
    author_email='me@lyshark.com',
    python_requires=">=3.6.0",
    license = "MIT Licence",
    packages=packages,
    include_package_data = True,
    platforms = "any"
    )
