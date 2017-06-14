#!/usr/bin/python2.7

# Copyright (c) 2015 Lukas Rist

import unittest

import oschameleon


class TestFabricHealthRules(unittest.TestCase):
    def test_module(self):
self.assertTrue(oschameleon.__title__ == 'oschameleon')