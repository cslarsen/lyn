from setuptools import setup

setup(
    name="lyn",
    packages=["lyn"],
    version="0.0.7",
    description="Python bindings for GNU Lightning",
    author="Christian Stigen Larsen",
    author_email="csl@csl.name",
    url="https://github.com/cslarsen/lyn",
    download_url="https://github.com/cslarsen/lyn/tarball/v0.0.7",
    license="https://www.gnu.org/licenses/lgpl-2.1.html",
    long_description=open("README.rst").read(),
    zip_safe=True,
    test_suite="tests",

    install_requires=[
        "enum34",
        "six",
        #"capstone", # TODO: Make this optional
    ],

    keywords=["jit", "compilation", "bytecode", "assembly", "just-in-time",
        "compiler", "machine code", "native code", "speed", "gnu", "lightning",
        "fast", "compile", "c", "ffi", "ctypes"],

    platforms=['unix', 'linux', 'osx', 'cygwin', 'win32'],

    classifiers=[
        "Development Status :: 3 - Alpha",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: Unix",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
)
