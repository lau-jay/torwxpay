#!/usr/bin/env python3
# coding=utf-8
# author Pyclearl
# Base code fork from https://github.com/pyclear/wzhifuSDK

import json
import time
import random
import hashlib
from urllib.parse import quote
from xml.etree import ElementTree

from tornado import gen
from tornado.httpclient import AsyncHTTPClient


# The following is wechat pay current URL, please check before using.
UNIFIED_ORDER_URL = 'https://api.mch.weixin.qq.com/pay/unifiedorder'
ORDER_QUERY_URL = 'https://api.mch.weixin.qq.com/pay/orderquery'


class HtppClient:
    @staticmethod
    @gen.coroutine
    def post_xml(url, data=None):
        try:
            request = AsyncHTTPClient(force_instance=True,
                                      defaults={'Content-Type': 'text/xml'})
            res = yield request.fetch(url, method='POST', body=data)
        except Exception as e:
            return {}
        else:
            result = res.body.decode('utf8')
            return result

    @staticmethod
    @gen.coroutine
    def post_xml_ssl(url, method='POST', data=None):
        # TODO 附带证书没做
        try:
            request = AsyncHTTPClient(force_instance=True,
                                      defaults={'Content-Type': 'text/xml'})
            res = yield request.fetch(url, method=method, body=data)
        except Exception as e:
            return {}
        else:
            result = res.body.decode('utf8')
            return result


class WxPayBasic:
    """
       WxPay Base Class
    """
    def trim_string(self, value):
        if value is not None and len(value) == 0:
            value = None
        return value

    def random_str(self, length=16):
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        sa = []
        for _ in range(length):
            sa.append(random.choice(chars))
        return ''.join(sa)

    def format_query_param(self, params, is_urlencode=False):
        """
        order params
        >>> params = {'appid': 'wxd930ea5d5a258f4f', 'mch_id': '10000100', 'device_info': 1000,
        ... 'body': 'test', 'nonce_str': 'ibuaiVcKdpRxkhJA'}
        >>> wxpay = WxPayBasic()
        >>> wxpay.format_query_param(params)
        'appid=wxd930ea5d5a258f4f&body=test&device_info=1000&mch_id=10000100&nonce_str=ibuaiVcKdpRxkhJA'
        """
        ordered_params = sorted(params)
        tmp = []
        for k in ordered_params:
            v = quote(params[k]) if is_urlencode else params[k]
            tmp.append("{0}={1}".format(k, v))
        return "&".join(tmp)

    def gen_sign(self, params, sign_type='MD5', app_key=None):
        """
        gen sign
        default sign type 'MD5', testing data from official document
        >>> params = {'appid': 'wxd930ea5d5a258f4f', 'mch_id': '10000100', 'device_info': 1000,
        ... 'body': 'test', 'nonce_str': 'ibuaiVcKdpRxkhJA'}
        >>> app_key = '192006250b4c09247ec02edce69f6a2d'
        >>> wxpay = WxPayBasic()
        >>> wxpay.gen_sign(params, app_key=app_key)
        '9A0A8659F005D6984697E2CA0A9CF3B7'
        """
        algo_map = {'MD5': hashlib.md5, 'SHA256': hashlib.sha256}

        # 签名步骤一：按字典序排序参数,format_query_param已做
        ordered_string = self.format_query_param(params, False)
        # 签名步骤二：在string后加入KEY
        raw_string = "{0}&key={1}".format(ordered_string, app_key)
        # 签名步骤三：加密
        sign = algo_map[sign_type](raw_string.encode('utf8')).hexdigest()
        # 签名步骤四：所有字符转为大写
        result_ = sign.upper()
        return result_

    def to_xml(self, params):
        """dict to xml"""
        xml = ["<xml>"]
        for k, v in params.items():
            if v.isdigit():
                xml.append("<{0}>{1}</{0}>".format(k, v))
            else:
                xml.append("<{0}><![CDATA[{1}]]></{0}>".format(k, v))
        xml.append("</xml>")
        return "".join(xml)

    def to_dict(self, xml):
        """xml to dict"""
        dom_tree = ElementTree.fromstring(xml)
        data = {node.tag: node.text for node in dom_tree}
        return data

    @gen.coroutine
    def post_xml_async(self, url, xml):
        """以post方式提交xml到对应的接口url"""
        res = yield HtppClient.post_xml(url, xml)
        return res

    @gen.coroutine
    def post_xml_SSL_async(self, url, xml):
        """使用证书，以post方式提交xml到对应的接口url"""
        res = yield HtppClient.post_xml_SSL(url, xml)
        return res


class WxPayClient(WxPayBasic):
    """请求型接口的基类"""
    response = None  # 微信返回的响应
    url = None      # 接口链接

    def __init__(self, appid='', mch_id='', app_key=''):
        self.parameters = {}  # 请求参数
        self.result = {}      # 返回参数
        self.appid = appid
        self.mch_id = mch_id
        self.app_key = app_key
        assert all([appid, mch_id, app_key]), 'argument missing'

    def set_params(self, params):
        """设置请求参数"""
        for k, v in params.items():
            self.parameters[self.trim_string(k)] = self.trim_string(v)

    def create_xml(self):
        """设置标配的请求参数，生成签名，生成接口参数xml"""
        self.parameters["appid"] = self.appid  # 公众账号ID
        self.parameters["mch_id"] = self.mch_id   # 商户号
        self.parameters["nonce_str"] = self.random_str()   # 随机字符串
        self.parameters["sign"] = self.gen_sign(self.parameters, app_key=self.app_key)  # 签名
        return self.to_xml(self.parameters)

    @gen.coroutine
    def get_result(self):
        """获取结果，默认不使用证书"""
        yield self.post_xml()
        self.result = self.to_dict(self.response)

    @gen.coroutine
    def post_xml(self):
        xml = self.create_xml()
        self.response = yield self.post_xml_async(self.url, xml)


class UnifiedOrder(WxPayClient):
    """统一支付接口类"""
    def __init__(self, appid='', mch_id='', app_key=''):
        # 设置接口链接
        self.url = UNIFIED_ORDER_URL
        self.appid = appid
        self.mch_id = mch_id
        self.app_key = app_key
        assert all([appid, mch_id, app_key]), 'argument mssing'

    def create_xml(self):
        """生成接口参数xml"""
        # 检测必填参数
        if any(self.parameters[key] is None for key in ("out_trade_no", "body",
                                                        "total_fee", "notify_url", "trade_type")):
            raise ValueError("missing parameter")
        if self.parameters["trade_type"] == "JSAPI" and self.parameters["openid"] is None:
            raise ValueError("JSAPI need openid parameters")

        self.parameters["appid"] = self.appid  # 公众账号ID
        self.parameters["mch_id"] = self.mch_id  # 商户号
        self.parameters["spbill_create_ip"] = "127.0.0.1"  # 终端ip
        self.parameters["nonce_str"] = self.random_str()  # 随机字符串
        self.parameters["sign"] = self.gen_sign(self.parameters, app_key=self.app_key)  # 签名
        return self.to_xml(self.parameters)

    @gen.coroutine
    def get_prepay_id(self):
        """获取prepay_id"""
        yield self.get_result()
        return self.result.get("prepay_id", '')


class UnifiedOrderH5(WxPayClient):
    """
      H5支付--微信外H5网页端掉调起支付接口
    """
    def __init__(self, appid='', mch_id='', app_key=''):
        # 设置接口链接
        self.url = UNIFIED_ORDER_URL
        self.appid = appid
        self.mch_id = mch_id
        self.app_key = app_key
        assert all([appid, mch_id, app_key]), 'argument mssing'

    def create_xml(self):
        """生成接口参数xml"""
        # 检测必填参数
        if any(self.parameters[key] is None for key in ("out_trade_no", "body", "spbill_create_ip",
                                                        "total_fee", "notify_url", "trade_type")):
            raise ValueError("missing parameter")
        if self.parameters["trade_type"] == "JSAPI" and self.parameters["openid"] is None:
            raise ValueError("H5 JS API need openid parameters")

        self.parameters["appid"] = self.app_id  # 公众账号ID
        self.parameters["mch_id"] = self.mch_id  # 商户号
        self.parameters["nonce_str"] = self.random_str()  # 随机字符串
        self.parameters["sign"] = self.gen_sign(self.parameters, app_key=self.app_key)  # 签名
        return self.to_xml(self.parameters)

    @gen.coroutine
    def get_prepay_id(self):
        """获取prepay_id"""
        yield self.get_result()
        return self.result.get("prepay_id", '')

    @gen.coroutine
    def get_mweb_url(self):
        yield self.get_result()
        return self.result.get('mweb_url', '')

    @gen.coroutine
    def get_data(self):
        yield self.get_result()
        return self.result


class UnifiedOrderAPP(WxPayClient):
    """
      APP支付
    """
    def __init__(self, appid='', mch_id='', app_key=''):
        # 设置接口链接
        self.url = UNIFIED_ORDER_URL
        self.appid = appid
        self.mch_id = mch_id
        self.app_key = app_key
        assert all([appid, mch_id, app_key]), 'argument mssing'

    def create_xml(self):
        """生成接口参数xml"""
        # 检测必填参数
        if any(self.parameters[key] is None for key in ("out_trade_no", "body", "spbill_create_ip",
                                                        "total_fee", "notify_url", "trade_type")):
            raise ValueError("missing parameter")

        if self.parameters["trade_type"] != "APP":
            raise ValueError("trade_type require string APP")

        # 另外申请的app支付的appid
        # app支付会另外生成商户号。特别坑
        self.parameters["appid"] = self.appid
        self.parameters["mch_id"] = self.mch_id
        self.parameters["nonce_str"] = self.random_str()  # 随机字符串
        self.parameters["sign"] = self.gen_sign(self.parameters, app_key=self.app_key)  # 签名
        return self.to_xml(self.parameters)

    @gen.coroutine
    def get_ticket(self):
        yield self.get_result()
        data = {}
        # 吐槽下微信的字段命名之分裂
        data['prepayid'] = self.result.get("prepay_id")
        data['appid'] = self.appid
        data['partnerid'] = self.mch_id
        data['package'] = "Sign=WXPay"
        data['noncestr'] = self.random_str()
        data['timestamp'] = str(int(time.time()))
        data['sign'] = self.gen_sign(data, app_key=self.app_key)
        if any(value is None for value in data.values()):
            data = {}
        return data


class JsApi(WxPayBasic):
    """
      JSAPI 支付--微信内H5网页端掉调起支付接口
    """
    prepay_id = None  # 使用统一支付接口得到的预支付id
    timestamp = int(time.time())

    def __init__(self, appid='', app_key=''):
        self.appid = appid
        self.app_key = app_key
        assert all([appid, app_key]), 'argument mssing'

    def set_prepay_id(self, prepay_id):
        """设置prepay_id"""
        self.prepay_id = prepay_id

    def get_parameters(self):
        js_api_obj = {}
        js_api_obj["appId"] = self.appid
        js_api_obj["timeStamp"] = "{0}".format(self.timestamp)
        js_api_obj["nonceStr"] = self.random_str()
        js_api_obj["package"] = "prepay_id={0}".format(self.prepay_id)
        js_api_obj["signType"] = "MD5"
        js_api_obj["paySign"] = self.gen_sign(js_api_obj, app_key=self.app_key)
        return json.dumps(js_api_obj)


class QR(WxPayClient):
    def __init__(self, appid='', mch_id='', app_key=''):
        self.appid = appid
        self.mch_id = mch_id
        self.app_key = app_key
        assert all([appid, mch_id, app_key]), 'argument mssing'

    def create_xml(self):
        """生成接口参数xml"""
        # 检测必填参数
        if any(self.parameters[key] is None for key in ("out_trade_no", "body", "spbill_create_ip",
                                                        "total_fee", "notify_url", "trade_type")):
            raise ValueError("missing parameter")

        self.parameters["appid"] = self.appid  # 公众账号ID
        self.parameters["mch_id"] = self.mch_id  # 商户号
        self.parameters["nonce_str"] = self.random_str()  # 随机字符串
        self.parameters["sign"] = self.gen_sign(self.parameters, app_key=self.app_key)  # 签名
        return self.to_xml(self.parameters)

    @gen.coroutine
    def get_code_url(self):
        """获取prepay_id"""
        yield self.get_result()
        return self.result.get("code_url", '')


class MiniProgram(WxPayClient):
    def __init__(self, appid='', mch_id='', app_key=''):
        self.appid = appid
        self.mch_id = mch_id
        self.app_key = app_key
        assert all([appid, mch_id, app_key]), 'argument mssing'

    def create_xml(self):
        """生成接口参数xml"""
        # 检测必填参数
        if any(self.parameters[key] is None for key in ("out_trade_no", "body", "spbill_create_ip",
                                                        "total_fee", "notify_url", "trade_type")):
            raise ValueError("missing parameter")

        self.parameters["appid"] = self.appid  # 小程序ID
        self.parameters["mch_id"] = self.mch_id  # 商户号, 注意开通小程序支付
        self.parameters["nonce_str"] = self.random_str()  # 随机字符串
        self.parameters["sign"] = self.gen_sign(self.parameters, app_key=self.app_key)  # 签名
        return self.to_xml(self.parameters)

    @gen.coroutine
    def get_prepay_id(self):
        """获取prepay_id"""
        yield self.get_result()
        return self.result.get("prepay_id", '')

    @staticmethod
    @gen.coroutine
    def get_weixin_pay_data(self):
        prepay_id = yield self.get_prepay_id()
        assert prepay_id, '获取prepay_id失败'

        again_sign = {}
        again_sign["appId"] = self.appid  # 小程序ID
        again_sign["timeStamp"] = int(time.time())  # 时间戳从1970年1月1日00:00:00至今的秒数,即当前的时间
        again_sign["nonceStr"] = self.create_onceStr()  # 随机字符串
        again_sign["package"] = "prepay_id={0}".format(prepay_id)
        again_sign["signType"] = "MD5"
        again_sign["paySign"] = self.gen_sign(again_sign, app_key=self.app_key)  # 签名
        del again_sign["appId"]
        return again_sign


class OrderQuery(WxPayClient):
    """订单查询接口"""
    def __init__(self, appid='', mch_id='', app_key=''):
        self.appid = appid
        self.mch_id = mch_id
        self.app_key = app_key
        assert all([appid, mch_id, app_key]), 'argument mssing'

    def create_xml(self):
        """生成接口参数xml"""

        # 二者必填其一
        if not any(self.parameters.get(key, '') for key in ("out_trade_no", "transaction_id", )):
            raise ValueError("missing parameter")

        self.parameters["appid"] = self.appid  # 公众账号ID
        self.parameters["mch_id"] = self.mch_id  # 商户号
        self.parameters["nonce_str"] = self.random_str()  # 随机字符串
        self.parameters["sign"] = self.gen_sign(self.parameters, app_key=self.app_key)  # 签名
        return self.to_xml(self.parameters)


class WxPayNotify(WxPayBasic):
    """响应型接口基类"""
    SUCCESS, FAIL = "SUCCESS", "FAIL"

    def __init__(self):
        self.data = {}  # 接收到的数据
        self.return_parameters = {}  # 返回参数

    def save_data(self, xml):
        """将微信的请求xml转换成dict，以方便数据处理"""
        self.data = self.to_dict(xml)

    def check_sign(self):
        """校验签名"""
        tmp_data = dict(self.data)  # make a copy to save sign
        del tmp_data['sign']
        sign = self.gen_sign(tmp_data)  # 本地签名
        if self.data['sign'] == sign:
            return True
        return False

    def get_data(self):
        """获取微信的请求数据"""
        return self.data

    def set_return_parame(self, parameter, parameterValue):
        """设置返回微信的xml数据"""
        self.return_parameters[self.trim_string(parameter)] = self.trim_string(parameterValue)

    def create_xml(self):
        """生成接口参数xml"""
        return self.to_xml(self.return_parameters)

    def response_xml(self):
        """将xml数据返回微信"""
        response_xml = self.create_xml()
        return response_xml


class Notify(WxPayNotify):
    """通用通知接口"""
    pass


if __name__ == '__main__':
    import doctest
    doctest.testmod(verbose=True)
