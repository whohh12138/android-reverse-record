# -*- coding: utf-8 -*-
"""
本地 CTF 重放脚本：手机号段 -> 登录 -> 商品列表 -> 详情 -> beforeinit -> compose。

整条链路（来自 reqable-captures/login2.har + compose2.har，App 1.9.12 / 1912 版反编译源码全量核对）：

    phonesegment (GET app.../config/check/phoneSegment)
    -> login      (POST app.../user/register/login)
    -> 商品列表    (GET app.../mall/item/list/cloudShopV6)
    -> 商品详情    (GET static.../mall/item/detailV2/IMTP1000004, spuId=1865)
    -> purchaseInfoV2 (POST h5.../mall/item/purchaseInfoV2)
    -> beforeinit (POST h5.../trade/order/standard/beforeinit)
    -> address-query (GET h5.../user/address/ship/query；compose 的 shipAddressId 取 dft=true 默认地址)
    -> compose    (POST app.../trade/order/standard/compose)
    -> submit     (POST app.../trade/order/standard/submit；transactionId/userAddress/
                   deliverMethodList/promIdList 全部取自 compose 响应，见 r0capture/i茅台-1788920768.log)
    -> pay        (POST app.../trade/order/pay；orderId 取自 submit 响应，头不带 MT-K/MT-V/MT-BIZID/MT-Info)

参数生成（能还原的都在 Java 层/来自身份；native 强依赖仅保留抓包常量）：

    MT-Device-ID  = clips(RAW_DEVICE)                 # ka.a.a() -> UUID.randomUUID() -> MD5,UTF-8 -> RAW_DEVICE = <32位MD5，原值已移除>
    MT-R          = clips("root/0;debug/0;proxy/0;inject/0")   # x8/a.java + MtCrypUtil
    MT-SN         = clips("2f5ae2348f427a666876d7da3563a7d2")  # com.netease.security.key.c.b() -> signatures[0] -> MD5 -> 2f5ae2348f427a666876d7da3563a7d2
    MT-K          = str(now_ms)                       # pairB = new RandK().b("" + System.currentTimeMillis(), RAW_DEVICE, "");  -> pairB.first
    MT-V          = mixK(now_ms, RAW_DEVICE, "")      # librand.so 的 RandK.mixK（已还原，见下方注）  -> pairB.second
    MT-Info       = "a3f9c2b8471de05f9b6c4e1287d5a9c1" # dex 编译期常量
    actParam      = AES256-CBC(compose 明文 JSON)     # com/moutai/mall/util/b.java (AesEncryptionUtil)

【RandK.mixK 还原】（librand.so，aarch64；函数名 MIX，gaes 实为 MD5）
  1) 拼接 base = "android" + 时间戳 + 设备raw + 第三参("")
  2) versionName = Version.getVN()（App "1.9.12"）追加到 base
  3) 从 37 字符 randC="01234567890abcdefghijklmnopqrstuvwxyz" 取一个随机字符 c
     （= libc rand()%37，App 每次请求随机）
  4) Version.getAN() 不是 "com.moutai.mall" 时追加 "error" + c + 时间戳
  5) getMd5S()(签名MD5) 未命中白名单
     {dd6c1787c17943e9db0c59c0da3d20e5, 2f5ae2348f427a666876d7da3563a7d2}
     时再次追加 "error" + c + 时间戳
  6) base 逐个字符升序排序（冒泡排序）；排序后再追加 c
  7) MT-V = MD5(base + c)[0:26] + c
  已用抓包 (MT-K,MT-V) 两组回归完全一致。

用法：
    python order_flow.py            # dry-run，只打印请求
    python order_flow.py --send     # 真实发送全流程（到 submit 为止，不含 pay）
    python order_flow.py vcode --send  # 只发送指定的一个请求
    python order_flow.py submit --send # 单独提交订单（自动先 compose 拿参数）
    python order_flow.py pay --send    # 单独支付下单（自动先 compose+submit 拿参数）
"""
import argparse
import base64
import hashlib
import json
import random
import time
import uuid

from curl_cffi import requests as creq

APP = "https://app.moutai519.com.cn"
H5 = "https://h5.moutai519.com.cn"
STATIC = "https://static.moutai519.com.cn"

PHONE = ""                  # 原值已移除；填入手机号
VCODE = ""                  # 原值已移除；填入短信验证码
SPU = "1865"                # 金王子 spuId（详情接口 defaultSkuId=1865）
ITEM_ID = "IMTP1000004"     # 金王子商品 id（列表 itemCode=1865 ↔ 详情 spuId）
STORE = "200000000001"      # 店铺：贵州茅台酱香酒营销有限公司
ADDRESS = 0                 # 原值已移除；收货地址 shipAddressId，正常会被 address-query 结果覆盖

# ka.a.a() -> UUID.randomUUID() -> MD5,UTF-8 -> RAW_DEVICE = <32位MD5，原值已移除>
# RAW_DEVICE = str(uuid.uuid4())
# 与下方 TOKEN 配对：该 token 由手机 App 登录签发，设备声明 clips_…，反解 raw 即此值
RAW_DEVICE = "0123456789abcdef0123456789abcdef"  # 原值已移除；填入自己设备的 raw id
# 37 字符表（librand.so .data randC），混入 MT-V 尾部的随机字符来源
RAND_CHAR = "01234567890abcdefghijklmnopqrstuvwxyz"

MT_INFO = "a3f9c2b8471de05f9b6c4e1287d5a9c1"
VERSION = "1.9.12"
PACKAGE_NAME = "com.moutai.mall"
SIGNATURE_MD5 = "2f5ae2348f427a666876d7da3563a7d2"
VALID_SIGNATURE_MD5S = {
    "2f5ae2348f427a666876d7da3563a7d2",
    "dd6c1787c17943e9db0c59c0da3d20e5",
}
# 以下两个来自 native 安全库/编译期常量，无法在 Java 层还原，取抓包值
BS_DVID = ""                # 原值已移除；native 安全库抓包值（当前未在请求头启用）
DTIME = "Wed Mar 25 06:44:09 GMT+08:00 2026"   # new Date(Build.TIME).toString()，构建期常量

# 采集点：登录响应 data.token；算法：服务端签发 JWT，脚本不自行伪造；赋值点：后续 app 请求 MT-Token。
# 非空则跳过 phoneSegment/vcode/login，直接使用已有登录态（注意：手机 App 再次登录会使之失效）
TOKEN = ""                  # 原值已移除；填入登录响应 data.token（非空则跳过登录三步）
# 采集点：同一次登录响应 data.cookie（与 TOKEN 同源成对）；赋值点：h5 域 Cookie MT-Token-Wap。
WAP_TOKEN = ""              # 原值已移除；与 TOKEN 同源成对，填入登录响应 data.cookie

# 每次真实发送的请求/响应追加记录到本文件（相对脚本运行目录）
RUN_LOG = "order_flow_run.log"

# 采集点：环境串、设备 raw ID、安全库明文（均来自 App 运行期）。
# 算法：y8/b.java 逐字符链式异或(seed=72)，再 Base64.NO_WRAP 并加 clips_。
# 赋值点：ApiInterceptor 注入 MT-R/MT-Device-ID/MT-SN，beforeinit 写入 mtr/deviceId。
def clips(plain: str) -> str:
    """Java y8/b.java MtCrypUtil.a 的 clips_ 包装。"""
    key, out = 72, []
    for ch in plain:
        key ^= ord(ch)
        out.append(key)
    return "clips_" + base64.b64encode(bytes(out)).decode()


# 采集点：MT-K 取 System.currentTimeMillis()；设备 raw 来自 bd.a.c()；Version.getVN() 取 versionName。
# 算法：librand.so/MIX 拼接 android+MT-K+raw+third+version，校验包名/签名，升序排序；
#       randC 取 c；gaes 实为 MD5，输出 MD5(...+c) 前 26 位再拼 c。
# 赋值点：订单业务层 ComposeOrderActivity 把结果写入 compose 请求头 MT-V。
def mixk(ts: int, device: str, third: str = "") -> str:
    """librand.so RandK.mixK(timestamp, device, third)。见文件头算法说明。"""
    ts_text = str(ts)
    c = random.choice(RAND_CHAR)               # libc rand()%37
    base = "android" + ts_text + device + third + VERSION
    if not PACKAGE_NAME or PACKAGE_NAME.casefold() != "com.moutai.mall":
        base += "error" + c + ts_text
    if not SIGNATURE_MD5 or SIGNATURE_MD5.casefold() not in VALID_SIGNATURE_MD5S:
        base += "error" + c + ts_text
    base = "".join(sorted(base))               # native 冒泡排序，逐字节升序
    # for char in RAND_CHAR:
    #     h = hashlib.md5((base + char).encode("utf-8")).hexdigest()
    #     print(h[:26] + char)
    h = hashlib.md5((base + c).encode("utf-8")).hexdigest()
    return h[:26] + c


# 采集点：ComposeOrderActivity 组装 ComposeOrderRequest 的配送、地址、商品、自提/优惠字段。
# 算法：Moshi 按字段顺序序列化 JSON；util/b.java 用固定 AES-256-CBC/PKCS7 加密，再 Base64.NO_WRAP。
# 赋值点：ComposeOrderRequestWrapper 的 actParam 字段，随 compose body 发送。
def act_param(body: dict) -> str:
    """com/moutai/mall/util/b.java 的 AesEncryptionUtil。"""
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise SystemExit("需要 pycryptodome：pip install pycryptodome") from exc
    key = b"3a79d$e4c2169a#fbd24c583ae71c0b9"
    iv = b"7392645081974362"
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    pad = 16 - len(raw) % 16
    return base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(raw + bytes([pad]) * pad)).decode()


# 采集点：compose 响应 transactionId/userAddress/deliverMethodList/promIdList/payChannelList；
#         addressInfo 空 String/Boolean 字段模板取自 r0capture/i茅台-1788920768.log submit 抓包解密。
# 算法：SubmitOrderRequest 整体 AES 成 actParam；外层 Wrapper 明文字段序与 actParam 键序均按抓包。
# 赋值点：/xhr/front/trade/order/standard/submit 的 body（源码 module/order/ComposeOrderActivity.order()）。
def submit_body(cdata: dict) -> dict:
    """按 App SubmitOrderRequestWrapper 字段序构造 submit 外层 body。"""
    d = cdata["data"]
    ua = d["userAddress"]
    address = {
        "address": "", "cityId": "", "cityName": "", "dft": False,
        "districtId": "", "districtName": "",
        "fullAddress": ua["fullAddress"], "mobile": ua["mobile"], "name": ua["name"],
        "provinceId": "", "provinceName": "", "shipAddressId": ua["shipAddressId"],
        "townId": "", "townName": "", "userId": d["userId"],
        "grey": False, "recent": False, "legal": False, "illegalText": "",
        "longitude": "", "latitude": "", "province": "", "city": "", "district": "",
    }
    plain = {
        "transactionId": d["transactionId"],
        "deliverMethod": d["deliverMethod"],
        "itemList": [{"storeId": STORE, "spuId": SPU, "count": 1}],
        "addressInfo": address,
        "payChannel": d["payChannelList"][0]["type"],
        "deliverMethodList": d["deliverMethodList"],
        "promIdList": d["promIdList"],
        "source": "", "sourceId": "", "ignorePromInconsistent": False,
    }
    return {
        "transactionId": plain["transactionId"],
        "deliverMethod": plain["deliverMethod"],
        "itemList": plain["itemList"],
        "actParam": act_param(plain),
        "addressInfo": address,
        "payChannel": plain["payChannel"],
        "source": "", "sourceId": "",
        "ignorePromInconsistent": False,
    }


def app_headers(token="", ts=None):
    """x8/a.java ApiInterceptor 的 MT-* 设备/请求头。"""
    ts = int(time.time() * 1000) if ts is None else ts
    return {
        "MT-Token": token,
        "User-Agent": f"android;36;google;lynx",
        "MT-Device-ID": clips(RAW_DEVICE),
        "MT-APP-Version": VERSION,
        # UUID.randomUUID().toString()
        "MT-Request-ID": str(uuid.uuid4()),
        "MT-Network-Type": "WIFI",
        "MT-R": clips("root/0;debug/0;proxy/0;inject/0"),
        "MT-Bundle-ID": "com.moutai.mall",
        "MT-USER-TAG": "0",
        "MT-SN": clips("2f5ae2348f427a666876d7da3563a7d2"),
        # new Date(Build.TIME).toString()
        "MT-DTIME": DTIME,
        "MT-RS": "1080*2400",
        # "BS-DVID": BS_DVID,
        "MT-DOUBLE": "0", "MT-SIM": "0", "MT-ACBE": "0", "MT-ACB": "0", "MT-ACBM": "0",
        "MT-K": str(ts),
        "MT-V": mixk(ts, RAW_DEVICE),
    }


# 采集点：H5/WebView 登录态走 Cookie(由 curl_cffi 会话管理)；算法：固定 WebView UA/Referer。
# 赋值点：h5 域名下的 purchaseInfoV2 / beforeinit。
def wap_headers():
    """H5/WebView 通道请求头（beforeinit/purchaseInfoV2 走 h5 域名）。"""
    return {
        "MT-APP-Version": VERSION,
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Chrome/134 Mobile Safari/537.36 moutaiapp/1.9.12",
        "Content-Type": "application/json",
        "Origin": H5,
        "Referer": f"{H5}/mt/item/detailV2?appConfig=2_1_2&id={ITEM_ID}",
    }


def main(step="all", send=False):
    s = creq.Session()

    def call(method, url, label, **kw):
        # submit/pay 的参数依赖上游响应，单独发包时自动先跑前置（compose 需要地址查询与 compose 链）
        pre = {"address-query": (),
               "compose": ("address-query",),
               "submit": ("address-query", "compose"),
               "pay": ("address-query", "compose", "submit")}.get(step, ())
        if step not in ("all", label) and label not in pre:
            return None
        print(f"[{label}] {method} {url}")
        print()
        print({**kw})
        print("\n")
        if not send:
            return None
        r = s.request(method, url, impersonate="chrome120", timeout=20, **kw)
        print(f"    -> HTTP {r.status_code}  {r.text[:200]}")
        with open(RUN_LOG, "a", encoding="utf-8") as lf:
            lf.write(f"[{time.strftime('%F %T')}] [{label}] {method} {url}\n")
            lf.write(f"REQ headers={kw.get('headers')}\nREQ params={kw.get('params')}\nREQ json={kw.get('json')}\n")
            lf.write(f"RESP HTTP {r.status_code} {r.text}\n\n")
        r.raise_for_status()
        return r

    login = None
    if not TOKEN:
        # 1. 手机号段校验
        call("GET", f"{APP}/xhr/front/mall/config/check/phoneSegment", "phoneSegment",
             params={"phone": PHONE, "requestType": "login"}, headers=app_headers())

        if step == "all":
            time.sleep(2)
        ts = int(time.time() * 1000)
        salt = "2af72f100c356273d46284f6fd1dfc08"
        call("POST", f"{APP}/xhr/front/user/register/vcode", "vcode",
             json={"md5":hashlib.md5((salt + PHONE + str(ts)).encode("utf-8")).hexdigest(),"mobile": PHONE, "timestamp": str(ts)}, headers={**app_headers(), "Content-Type": "application/json; charset=UTF-8","Accept-Encoding": "gzip"})
        # 2. 登录（返回 MT-Token）
        login = call("POST", f"{APP}/xhr/front/user/register/login", "login",
                     json={"vCode": VCODE, "mobile": PHONE, "ydToken": "", "ydLogId": ""},
                     headers={**app_headers(), "Content-Type": "application/json; charset=UTF-8"})
    else:
        # TOKEN 已填：跳过登录三步，直接使用已有登录态；h5 Cookie 用配套 WAP_TOKEN
        print("[skip] TOKEN 已填，跳过 phoneSegment/vcode/login")
        s.cookies.set("MT-Token-Wap", WAP_TOKEN, domain="h5.moutai519.com.cn", path="/")
        s.cookies.set("MT-Device-ID-Wap", clips(RAW_DEVICE), domain="h5.moutai519.com.cn", path="/")

    token = TOKEN
    if login and login.ok:
        try:
            data = login.json()["data"]
            token = data["token"]
            # WebView 登录态 Cookie：MTWebView.setCookie 注入的就是 data.cookie（与 token 签名不同）
            s.cookies.set("MT-Token-Wap", data["cookie"], domain="h5.moutai519.com.cn", path="/")
            s.cookies.set("MT-Device-ID-Wap", clips(RAW_DEVICE), domain="h5.moutai519.com.cn", path="/")
        except Exception:
            pass

    # 3. 商品列表
    call("GET", f"{APP}/xhr/front/mall/item/list/cloudShopV6", "item-list",
         headers=app_headers(token))

    # 4. 商品详情（金王子，spuId=1865）
    call("GET", f"{STATIC}/mt-backend/xhr/front/mall/item/detailV2/{ITEM_ID}", "item-detail",
         headers={"User-Agent": wap_headers()["User-Agent"], "Origin": H5, "Referer": f"{H5}/"})

    # 5. 购买信息校验
    call("POST", f"{H5}/xhr/front/mall/item/purchaseInfoV2", "purchaseInfo",
         json={"hot": False, "spuId": ITEM_ID, "shopId": STORE, "jt": "anonymous"},
         headers=wap_headers())

    # 6. beforeinit
    before = {
        "itemList": [{"count": 1, "spuId": SPU, "storeId": STORE}],
        "userInfoBaseContext": {
            "addressLat": "", "addressLng": "",  # 原坐标已移除，填入自选坐标
            "mtr": clips("root/0;debug/0;proxy/0;inject/0"),
            "deviceId": clips(RAW_DEVICE),
            "appUserAgent": "android;36;google;lynx",
        },
        "ydToken": "", "ydLogId": "", "shipAddressId": "",
    }
    call("POST", f"{H5}/xhr/front/trade/order/standard/beforeinit", "beforeinit",
         json=before, headers=wap_headers())

    # 7. 查询收货地址（下单必发；响应可缓存但包不可省，compose 的 shipAddressId 取 dft=true 默认地址）
    address_id = ADDRESS  # 兜底常量，正常都会被查询结果覆盖
    if step in ("all", "address-query", "compose", "submit", "pay"):
        aq = call("GET", f"{H5}/xhr/front/user/address/ship/query", "address-query",
                  params={"__timestamp": str(int(time.time() * 1000))}, headers=wap_headers())
        if aq is not None:
            alist = aq.json()["data"]["list"]
            addr = next((a for a in alist if a.get("dft")), alist[0])
            address_id = addr["shipAddressId"]
            print(f"[address-query] 默认地址 {address_id} {addr['fullAddress']} {addr['name']}")

    # 8. compose（下单确认页；submit/pay 单独发包时也会先跑到这里拿参数）
    compose_r = None
    if step in ("all", "compose", "submit", "pay"):
        compose_plain = {
            "deliverMethod": -1,
            "itemList": [{"storeId": STORE, "spuId": SPU, "count": 1}],
            "addressInfo": {"shipAddressId": address_id},
            "selfLatitude": "", "selfLongitude": "",
        }
        compose = {
            "deliverMethod": -1,
            "addressInfo": {"shipAddressId": address_id},
            "itemList": compose_plain["itemList"],
            "actParam": act_param(compose_plain),
        }
        h = app_headers(token)
        h.update({"MT-BIZID": "", "MT-Info": MT_INFO,
                  "Content-Type": "application/json; charset=UTF-8"})
        compose_r = call("POST", f"{APP}/xhr/front/trade/order/standard/compose", "compose",
                         json=compose, headers=h)

    # 8. submit（提交订单；transactionId/userAddress/deliverMethodList/promIdList/payChannel 全部来自 compose 响应）
    submit_r = None
    if step in ("all", "submit", "pay") and compose_r is not None:
        cdata = compose_r.json()
        if cdata.get("code") != 2000:
            print(f"[chain] compose 业务码 {cdata.get('code')}：{cdata.get('message')}，停止后续")
            return
        sh = app_headers(token)
        sh.update({"MT-BIZID": "", "MT-Info": MT_INFO,
                   "Content-Type": "application/json; charset=UTF-8"})
        submit_r = call("POST", f"{APP}/xhr/front/trade/order/standard/submit", "submit",
                        json=submit_body(cdata), headers=sh)

    # 9. pay（支付下单；orderId 来自 submit 响应；App 此包不带 MT-K/MT-V/MT-BIZID/MT-Info）
    #    不在 all 流程内，仅 python order_flow.py pay --send 单独发送（会自动先跑 compose+submit）
    if step == "pay" and submit_r is not None:
        sdata = submit_r.json()
        if sdata.get("code") != 2000:
            print(f"[chain] submit 业务码 {sdata.get('code')}：{sdata.get('message')}，停止后续")
            return
        ph = app_headers(token)
        ph.pop("MT-K"), ph.pop("MT-V")
        ph.update({"Content-Type": "application/json; charset=UTF-8"})
        call("POST", f"{APP}/xhr/front/trade/order/pay", "pay",
             json={"orderId": str(sdata["data"]["orderId"]), "payMethod": 0}, headers=ph)

    if not send:
        print("\n[dry-run] 未发送。确认后加 --send 真实发包。")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("step", nargs="?", default="all",
                    choices=("all", "phoneSegment", "vcode", "login", "item-list",
                             "item-detail", "purchaseInfo", "beforeinit", "address-query",
                             "compose", "submit", "pay"),
                    help="只执行指定请求，默认 all；compose/submit/pay 会自动先跑前置拿参数")
    ap.add_argument("--send", action="store_true", help="真实发包；默认只打印流程")
    args = ap.parse_args()
    main(args.step, args.send)
    # print(app_headers())
