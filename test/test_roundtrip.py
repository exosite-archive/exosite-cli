#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2016, Exosite, LLC
# All rights reserved
from __future__ import unicode_literals

# Test the CLI, using full round trip
import unittest
import subprocess
import requests
import shutil
import os
import errno

SOLUTIONFILE = 'test/.Solutionfile.secret'
HOST = 'bizapi.hosted.exosite.io'

class ExositeTest(unittest.TestCase):
    def exo(self, cmd=[], path=None):
        if path is None:
            path = self.path
        cwd = 'test' + path
        return subprocess.check_output(
            ['python', '../../../exosite.py'] + cmd,
            cwd='test' + path).decode('utf-8')

    '''Simulate running --init to put .Solutionfile.secret into a particular
       solution directory.'''
    def init(self, path=None):
        if path is None:
            path = self.path
        shutil.copyfile(SOLUTIONFILE, 'test' + path + '/.Solutionfile.secret')

    '''Simulate running --init to put .Solutionfile.secret into a particular
       solution directory.'''
    def deinit(self, path=None):
        if path is None:
            path = self.path
        if (len(path.strip()) == 0):
            raise Exception('Did you really mean to remove root secret Solutionfile?')
        try:
            os.remove('test' + path + '/.Solutionfile.secret')
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise e

'''Test a minimal solution'''
class TestEmpty(ExositeTest):
    def setUp(self):
        self.path = '/files/empty_solution'

    def test_usage_uninit(self):
        # this should actually return non-zero
        self.deinit()
        out = self.exo()
        self.assertTrue(out.startswith(u'No credential file found'))

    def test_usage_initted(self):
        self.init()
        out = self.exo()
        self.deinit()
        self.assertTrue(out.startswith('One option of'))

    def test_deploy(self):
        self.init()
        out = self.exo(['--deploy', '--host', HOST])
        self.deinit()
        print(out)
        url = out.strip().splitlines()[-1].split(': ')[1]
        response = requests.get(url)
        response.raise_for_status()
        self.assertEqual(response.text.strip(), 'Hello');


    #def test_deploy_minimal(self):
    #    c = subprocess.run(['cd', 'files/empty_solution', '&&', 'python ../../../exosite.py -v'
    #    self.assertEqual(c.returncode, 0)

    #def test_split(self):
    #    s = 'hello world'
    #    self.assertEqual(s.split(), ['hello', 'world'])
    #    # check that s.split fails when the separator is not a string
    #    with self.assertRaises(TypeError):
    #        s.split(2)

if __name__ == '__main__':
    unittest.main()
