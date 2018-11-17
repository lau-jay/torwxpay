# torwxpay
Tornado Asynchronous WeChat Pay Operation

### Important

* Python >= 3.6 required

### Usage

#### H5
 [Official document](https://pay.weixin.qq.com/wiki/doc/api/H5.php?chapter=9_1)
 
```
   from wxpay import WxPayH5
   from urllib.parse import quote_plus
   from conf import WechatConfig

   async def pay()
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
      wxpay = WxPayH5(appid=WechatConfig['appid'],
                                     mch_id=WechatConfig['mch_id'],
                                     app_key=WechatConfig['app_key'])
      try:
          mweb_url = await wxpay.get_mweb_url(**param)
      except Exception as e:
          """
            your code
          """
          return
      assert mweb_url
      return "{}&redirect_url={}".format(mweb_url, quote_plus(redirect_url))
```

#### JSAPI
```
   from wxpay import WxPayJsApi
   from conf import WechatConfig

   async def pay()
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
      wxpay = WxPayJsApi(appid=WechatConfig['appid'],
                                   mch_id=WechatConfig['mch_id'],
                                   app_key=WechatConfig['app_key'])
      try:
          js_data = wxpay.get_parameters(**params)
      except Exception as e:
          """
            your code
          """
          return
      assert js_data
      return js_data
```

#### APP
```
   from wxpay import WxPayAPP
   from conf import WechatConfig

   async def pay()
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
      wxpay = WxPayAPP(appid=WechatConfig['mobile_app_id'],
                                      mch_id=WechatConfig['mobile_mch_id'],
                                      app_key=WechatConfig['app_key'])
      try:
          data = await wxpay.get_ticket(**param)
      except Exception as e:
          """
            your code
          """
          return
      assert data
      return data

```
