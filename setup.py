from setuptools import setup

setup(
    name="lyn",
    packages=["lyn"],
    version="0.0.4",
    description="Python bindings for GNU Lightning JIT",
    author="Christian Stigen Larsen",
    author_email="csl@csl.name",
    url="https://github.com/cslarsen/lyn",
    download_url="https://github.com/cslarsen/lyn/tarball/v0.0.4",
    license="https://www.gnu.org/licenses/lgpl-2.1.html",
    long_description=open("README.rst").read(),
    zip_safe=True,
    test_suite="tests",

    install_requires=[
        "enum34",
        "capstone",
    ],

    keywords=["jit", "compilation", "bytecode", "assembly", "just-in-time",
        "compiler", "machine code", "native code", "speed"],

    platforms=['unix', 'linux', 'osx', 'cygwin', 'win32'],

    classifiers=[
        "Development Status :: 3 - Alpha",
        "Natural Language :: English",
    ],
)
