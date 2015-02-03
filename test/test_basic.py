import unittest

import oschameleon


class TestFabricHealthRules(unittest.TestCase):
    def test_module(self):
        self.assertTrue(oschameleon.__title__ == 'oschameleon')
