# torwxpay
Tornado Asynchronous WeChat Pay Operation

Base code fork for https://github.com/Skycrab/wzhifuSDK

### Usage

#### wx_pay_h5
 [Official document](https://pay.weixin.qq.com/wiki/doc/api/H5.php?chapter=9_1)
```
   from tornado import gen

   from wxpay import UnifiedOrderH5
   from urllib.parse import quote_plus
   from conf import WechatConfig

   @gen.coroutine
   def pay()
      redirect_url = 'm.example.com'
      scene_info = ''
      params = {
                  'device_info': 'WEB',
                  'sign_type': 'MD5',
                  'body': 'example',
                  'detail': 'example h5 pay',
                  'out_trade_no': 'zzz-xxxx-yyy',
                  'total_fee': 100,
                  'notify_url': 'http://example.com/notification',
                  'trade_type': 'MWEB',
                  "spbill_create_ip": "real_ip",
                  "scene_info": scene_info,
              }
      unified_order = UnifiedOrderH5(appid=WechatConfig['appid'],
                                     mch_id=WechatConfig['mch_id'],
                                     app_key=WechatConfig['app_key'])
      unified_order.set_params(params)
      try:
          data = yield unified_order.get_data()
      except Exception as e:
          """
            your code
          """
          return
      assert data.get('mweb_url')
      return "{}&redirect_url={}".format(data['mweb_url'], quote_plus(redirect_url))
```

#### wx_pay_jsapi
```
   from tornado import gen

   from wxpay import JsApi, UnifiedOrder
   from conf import WechatConfig

   @gen.coroutine
   def pay()
      redirect_url = 'public.example.com'
      params = {
                  'device_info': 'WEB',
                  'sign_type': 'MD5',
                  'body': 'example',
                  'detail': 'example h5 pay',
                  'out_trade_no': 'zzz-xxxx-yyy',
                  'total_fee': 100,
                  'notify_url': 'http://example.com/notification',
                  'trade_type': 'JSAPI',
                  "openid": "open_id",
                  "attach": redirect_url,
              }
      unified_order = UnifiedOrder(appid=WechatConfig['appid'],
                                   mch_id=WechatConfig['mch_id'],
                                   app_key=WechatConfig['app_key'])
      unified_order.set_params(params)
      jsapi = JsApi(appid=WechatConfig['appid'],
                    app_key=WechatConfig['app_key'])
      try:
          prepay_id = yield unified_order.get_prepay_id()
      except Exception as e:
          """
            your code
          """
          return
      assert prepay_id
      jsapi.set_prepay_id(prepay_id)
      return jsapi.get_parameters()
```

#### wx_pay_app
```
   from tornado import gen

   from wxpay import UnifiedOrderAPP

   @gen.coroutine
   def pay()
      params = {
                  'sign_type': 'MD5',
                  'body': 'example',
                  'detail': 'example h5 pay',
                  'out_trade_no': 'zzz-xxxx-yyy',
                  'total_fee': 100,
                  'notify_url': 'http://example.com/notification',
                  'trade_type': 'APP',
                  "spbill_create_ip": "real_ip",
              }
      unified_order = UnifiedOrderAPP(appid=WechatConfig['mobile_app_id'],
                                      mch_id=WechatConfig['mobile_mch_id'],
                                      app_key=WechatConfig['app_key'])
      unified_order.set_params(params)
      try:
          data = yield unified_order.get_ticket()
      except Exception as e:
          """
            your code
          """
          return
      assert data
      return data

```

