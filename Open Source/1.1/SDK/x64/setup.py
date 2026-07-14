import setuptools
from distutils.core import setup

packages = ['x64dbg']

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='x64dbg',
    version='1.1.0',
    author='lyshark',
    description='An automated testing plugin developed for the x64dbg debugger, used to quickly build Python based test scripts to accelerate the development of exploit programs, assist in vulnerability mining, and analyze malware.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email='me@lyshark.com',
    url="http://lyscript.lyshark.com",
    python_requires=">=3.6.0",
    license="MIT Licence",
    packages=packages,
    include_package_data=True,
    platforms="any",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        # Add any dependencies here
    ],
)
