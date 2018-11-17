#!/usr/bin/env python3
# coding=utf-8

import unittest
from tornado.testing import gen_test
from tornado.testing import AsyncTestCase
from wxpay import WxPayBasic
from wxpay import WxPayClient
from wxpay import UnifiedOrder
from wxpay import JsApi


class WxPayBasicTest(AsyncTestCase):
    basic = WxPayBasic()

    def test_trim_string(self):
        self.assertIsNone(self.basic.trim_string(''))
        self.assertIsNone(self.basic.trim_string([]))
        self.assertIsNone(self.basic.trim_string({}))
        self.assertEqual(self.basic.trim_string('123'), '123')

    def test_create_random_str(self):
        self.assertEqual(len(self.basic.random_str(32)), 32)
        self.assertNotEqual(len(self.basic.random_str(31)), 32)

    def test_format_query_param(self):
        params = {'axx': '123456', 'dcebc': 'xxxx', 'appid': 'asfas'}
        order_str = "appid=asfas&axx=123456&dcebc=xxxx"
        self.assertEqual(self.basic.format_query_param(params, False), order_str)


class UnifiedOrderTest(AsyncTestCase):
    pass


if __name__ == "__main__":
    unittest.main()
