# import unittest, sys
# 
# def test_suite():
#     suite = unittest.TestSuite()
#     if sys.version_info >= (2,4):
#         suite.addTests([doctest.DocFileSuite('test_clean.txt')])
#         # suite.addTests([doctest.DocFileSuite('test_clean_embed.txt')])
#     return suite

import doctest
doctest.testfile('test_clean.txt')
doctest.testfile('test_clean_embed.txt')