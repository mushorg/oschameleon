#!/usr/bin/python2.7

# Copyright (c) 2015 Lukas Rist

import unittest

import oschameleon


class TestBasic(unittest.TestCase):
    def test_title(self):
        self.assertTrue(oschameleon.__title__ == 'oschameleon')
