import json
import time
from tornado.httpclient import AsyncHTTPClient
from .utils import to_dict, to_xml, random_str, gen_sign

# The following is wechat pay current URL, please check before using.
UNIFIED_ORDER_URL = 'https://api.mch.weixin.qq.com/pay/unifiedorder'
ORDER_QUERY_URL = 'https://api.mch.weixin.qq.com/pay/orderquery'
CLOSE_ORDER_URL = "https://api.mch.weixin.qq.com/pay/closeorder"


class WeiXinPayParamError(ValueError):
    def __init__(self, msg):
        super().__init__(msg)


class WxPayBasic:
    """
       WxPay Base Class
    """

    def __init__(self, *, app_id=None, mch_id=None, app_key=None, key=None, cert=None):
        self.cert = cert
        self.key = key
        self.appid = app_id
        self.mch_id = mch_id
        self.app_key = app_key
        self.request = AsyncHTTPClient(force_instance=True,
                                       defaults={'Content-Type': 'text/xml'})
        assert all([app_id, mch_id, app_key]), 'argument missing'

    async def _post(self, url, *, data=None, is_ssl=False):

        assert data
        payload = dict()
        payload['method'] = 'POST'
        payload['body'] = to_xml(data)
        payload['raise_error'] = False
        if is_ssl:
            payload.update({'cert': (self.cert, self.key)})
        res = await self.request.fetch(url, **payload)
        result = to_dict(res.body.decode('utf8'))
        return result

    async def unified_order(self, **kwargs):
        if not all(kwargs.get(key, None) for key in ("out_trade_no", "body",
                                                     "total_fee", "notify_url",
                                                     "trade_type")):
            raise WeiXinPayParamError("get params {}, but missing parameter".format(kwargs))

        if kwargs["trade_type"] == "JSAPI" and not kwargs.get("openid", False):
            raise WeiXinPayParamError("trade_type is JSAPI need openid parameters")
        if kwargs["trade_type"] == "NATIVE" and not kwargs.get("product_id", False):
            raise WeiXinPayParamError("trade_type is NATIVE need product_id")

        payload = dict()
        payload.update(kwargs)
        payload["appid"] = self.appid
        payload["mch_id"] = self.mch_id
        if "spbill_create_ip" not in kwargs:
            payload["spbill_create_ip"] = "127.0.0.1"
        payload["nonce_str"] = random_str()
        payload["sign"] = gen_sign(payload, app_key=self.app_key)
        res = await self._post(UNIFIED_ORDER_URL, data=payload)
        return res

    async def query_order(self, **kwargs):
        # 二者必填其一
        if not any(kwargs.get(key, '') for key in ("out_trade_no", "transaction_id",)):
            raise ValueError("missing parameter")
        payload = dict()
        payload.update(kwargs)
        payload["appid"] = self.appid  # 公众账号ID
        payload["mch_id"] = self.mch_id  # 商户号
        payload["nonce_str"] = random_str()  # 随机字符串
        payload["sign"] = gen_sign(payload, app_key=self.app_key)  # 签名
        return await self._post(ORDER_QUERY_URL, data=payload)

    async def close_order(self, **kwargs):
        if not kwargs.get("out_trade_no", ''):
            raise ValueError("missing parameter out_trade_noe")
        payload = dict()
        payload.update(kwargs)
        payload["appid"] = self.appid  # 公众账号ID
        payload["mch_id"] = self.mch_id  # 商户号
        payload["nonce_str"] = random_str()  # 随机字符串
        payload["sign"] = gen_sign(payload, app_key=self.app_key)  # 签名
        return await self._post(CLOSE_ORDER_URL, data=payload)

    def replay(self, msg, ok=True):
        code = "SUCCESS" if ok else "FAIL"
        return to_xml(dict(return_code=code, return_msg=msg))

    async def prepay_id(self, **kwargs):
        res = await self.unified_order(**kwargs)
        prepay_id = res.get('prepay_id')
        return prepay_id


class WxPayApp(WxPayBasic):
    def __init__(self, **config):
        super().__init__(**config)

    async def get_ticket(self, **kwargs):
        payload = dict()
        payload['prepayid'] = await self.prepay_id(**kwargs)
        payload['appid'] = self.appid
        payload['partnerid'] = self.mch_id
        payload['package'] = "Sign=WXPay"
        payload['noncestr'] = random_str()
        payload['timestamp'] = str(int(time.time()))
        payload['sign'] = gen_sign(payload, app_key=self.app_key)
        if not all(value for value in payload.values()):
            payload = {}
        return payload


class WxPayJsApi(WxPayBasic):
    def __init__(self, **config):
        super().__init__(**config)

    def get_parameters(self, **kwargs):
        js_api_obj = dict()
        js_api_obj["appId"] = self.appid
        js_api_obj["timeStamp"] = int(time.time())
        js_api_obj["nonceStr"] = random_str()
        js_api_obj["package"] = "prepay_id={0}".format(self.prepay_id(**kwargs))
        js_api_obj["signType"] = "MD5"
        js_api_obj["paySign"] = gen_sign(js_api_obj, app_key=self.app_key)
        return json.dumps(js_api_obj)


class WxPayH5(WxPayBasic):
    def __init__(self, **config):
        super().__init__(**config)

    async def get_mweb_url(self, **kwargs):
        res = await self.unified_order(**kwargs)
        mweb_url = res.get("mweb_url", '')
        return mweb_url

    async def get_data(self, **kwargs):
        res = await self.unified_order(**kwargs)
        return res


class WxPayQR(WxPayBasic):
    def __init__(self, **config):
        super().__init__(**config)

    async def get_code_url(self, **kwargs):
        """获取prepay_id"""
        res = await self.unified_order(**kwargs)
        prepay_id = res.get("code_url", '')
        return prepay_id


class WxPayMiniProgram(WxPayBasic):
    def __init__(self, **config):
        super().__init__(**config)

    async def get_wx_pay_data(self, **kwargs):
        prepay_id = await self.prepay_id(**kwargs)
        assert prepay_id, '获取prepay_id失败'

        again_sign = dict()
        again_sign["appId"] = self.appid  # 小程序ID
        again_sign["timeStamp"] = str(int(time.time()))
        again_sign["nonceStr"] = random_str()
        again_sign["package"] = "prepay_id={0}".format(prepay_id)
        again_sign["signType"] = "MD5"
        again_sign["paySign"] = gen_sign(again_sign, app_key=self.app_key)
        del again_sign["appId"]
        return again_sign
