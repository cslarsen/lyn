# -*- encoding: utf-8 -*-

"""
lyn -- Bindings for GNU Lightning.

Copyright (C) 2015 Christian Stigen Larsen

Distributed under the LGPL v2.1 or later. You are allowed to change the license
on a particular copy to the LGPL v3.0, the GPL v2.0 or the GPL v3.0.
"""

from .lyn import (
    Lightning,
    State,
    char_p,
    word_t,
    wordsize,
)

from .registers import (
    F0,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    R0,
    R1,
    R2,
    R3,
    Register,
    V0,
    V1,
    V2,
    V3,
)

__all__ = [
    "F0",
    "F1",
    "F2",
    "F3",
    "F4",
    "F5",
    "F6",
    "F7",
    "Lightning",
    "R0",
    "R1",
    "R2",
    "R3",
    "Register",
    "State",
    "V0",
    "V1",
    "V2",
    "V3",
    "char_p",
    "word_t",
    "wordsize",
]

__author__ = "Christian Stigen Larsen"
__copyright__ = "Copyright 2015, Christian Stigen Larsen"
__credits__ = ["Christian Stigen Larsen"]
__email__ = "csl@csl.name"
__license__ = "LGPL"
__maintainer__ = "Christian Stigen Larsen"
__status__ = "Prototype"
__version__ = "0.0.7"
