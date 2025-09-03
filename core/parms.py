"""
获取加密参数的具体位置
"""
import base64
import binascii
import hashlib
import os
import random
import string
import time
from urllib import parse
import uuid
from datetime import datetime

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

models = [
    "Pixel 7", "Redmi K50", "ONEPLUS 9 Pro", "Vivo V23", "MI 12X",
    "SM-G998B", "Xiaomi 11T", "OPPO Reno8", "Pixel 7 Pro", "Lenovo Legion Y90",
    "Realme GT Neo3", "MI 11 Ultra", "Redmi Note 11", "ONEPLUS A6013", "VOG-L29",
    "P50 Pro", "OPPO Find X5", "Vivo X80", "Pixel 6a", "Redmi K40",
    "SM-G991U", "Xiaomi 12S", "Realme GT", "ONEPLUS 8T", "Vivo Y76",
    "OPPO Reno7", "MI 10 Pro", "Pixel 5", "Lenovo K12 Pro", "Redmi Note 10",
    "SM-G990F", "Xiaomi 11 Lite", "OPPO Find X3", "Vivo V21", "ONEPLUS 7T",
    "MI 9T", "Pixel 4 XL", "Realme X50 Pro", "Redmi K30", "SM-G988B",
    "Xiaomi Mi Mix 4", "OPPO Reno6", "Vivo X60", "Lenovo Legion 2 Pro", "ONEPLUS Nord 2",
    "Pixel 3a", "MI 8 Lite", "Redmi Note 9", "Realme 7 Pro", "SM-G985F",
    "Xiaomi Poco F3", "Pixel 6 Pro", "Redmi K20", "ONEPLUS 6T", "Vivo V19",
    "MI 11", "SM-G960F", "Xiaomi Mi 10", "OPPO Reno4", "Vivo X50",
    "Realme 6", "Lenovo Z6", "Pixel 5a", "Redmi Note 8", "ONEPLUS 5T",
    "MI 10T", "SM-G973F", "Xiaomi Mi 9", "OPPO Reno3", "Vivo Y20",
    "Realme X3", "Lenovo K10", "Pixel 4a", "Redmi Note 7", "ONEPLUS 6",
    "MI 9 SE", "SM-G970F", "Xiaomi Mi 8", "OPPO Reno2", "Vivo V17",
    "Realme 5 Pro", "Lenovo Z5", "Pixel 3 XL", "Redmi K30 Pro", "ONEPLUS 7",
    "MI 8 Pro", "SM-G965F", "Xiaomi Mi 8 Lite", "OPPO Reno", "Vivo Y17",
    "Realme 3 Pro", "Lenovo K8 Plus", "Pixel 2 XL", "Redmi Note 6 Pro", "ONEPLUS 5",
    "MI 6X", "SM-G955F", "Xiaomi Mi 6", "OPPO F11 Pro", "Vivo V15",
    "Realme 2 Pro", "Lenovo Z2 Plus", "Pixel 2", "Redmi Note 5", "ONEPLUS 3T"
]


def e(str_input):
    """对buvid取值"""
    return str_input[2] + str_input[12] + str_input[22]


def get_xw():
    """获取xw开头的buvid"""
    u = str(uuid.uuid4()).replace('-', '')
    return "XW{}{}".format(e(u), u).upper()


def get_buvid():
    """获取buvid"""
    buvid = get_xw()
    return buvid


def get_xx():
    """获取xx开头的buvid"""
    andriod_id = '5d01aa95f9aca38c'
    md5 = hashlib.md5()
    md5.update(andriod_id.encode())
    d4 = md5.hexdigest()
    return ('XX' + e(d4) + d4).upper()


def obfuscate_string(s: str) -> str:
    """型号加密，不补 Base64 '='"""
    # 1. 将字符串转换成字节数组
    bytes_arr = bytearray(s.encode('utf-8'))

    if not bytes_arr:
        return s

    # 2. 对第一个字节做异或运算
    bytes_arr[0] = bytes_arr[0] ^ (len(bytes_arr) & 0xFF)

    # 3. 从第二个字节开始，每个字节都和前一个字节异或
    for i in range(1, len(bytes_arr)):
        bytes_arr[i] = (bytes_arr[i - 1] ^ bytes_arr[i]) & 0xFF

    try:
        # 4. Base64 编码，URL-safe，并去掉结尾 '='
        encoded = base64.urlsafe_b64encode(bytes_arr)
        return encoded.decode('utf-8').rstrip('=')
    except Exception:
        # 5. 编码失败时返回原始字符串
        return s


def get_device_id():
    """获取device_id"""
    androidId = '5d01aa95f9aca38c'

    model = random.choice(models)
    modelHash = model.replace(' ', '').strip()
    return obfuscate_string(androidId + "@" + modelHash)


def get_model_band_md5(buvid):
    """对手机和品牌进行md5加密"""
    band = 'g8998-00034-2006052136'  # 这里先直接写死
    model = random.choice(models)  # 这里先直接写死
    s = buvid + model + band
    md5 = hashlib.md5()
    md5.update(s.encode('utf-8'))
    return md5.hexdigest()


def h():
    """生成时间戳"""
    # 获取当前时间
    now = datetime.now()
    # 按 "yyyyMMddHHmmss" 格式输出
    return now.strftime("%Y%m%d%H%M%S")


def g():
    """生成 8 个随机字节"""
    random_bytes = os.urandom(8)
    # 转成十六进制字符串
    return random_bytes.hex()


def b(fpEntity: str) -> str:
    # 限制长度到 63
    length = min(len(fpEntity), 63)
    i = 0
    # 每 2 个字符累加（16进制解析）
    for j in range(0, length - 1, 2):
        substring = fpEntity[j:j + 2]
        i += int(substring, 16)
    # 对 256 取余并转成 2 位 hex
    return f"{i % 256:02x}"


def get_fp_local(buvid):
    """获取fp_local"""
    model_band = get_model_band_md5(buvid)
    # 生成时间戳
    tt = h()
    # 生成随机8位
    random_str = g()
    sttr = model_band + tt + random_str
    return sttr + b(sttr)


def get_session_id():
    """获取session_id"""
    b_arr = random.randbytes(4)  # 生成 4 个随机字节
    return binascii.hexlify(b_arr).decode('utf-8')


def get_sign(param):
    """获取sign"""
    obj = hashlib.sha256()
    key = '9cafa6466a028bfb'
    obj.update(param.encode('utf-8'))
    obj.update(key.encode('utf-8'))
    return obj.hexdigest()


def aes_encrypt(body: str) -> bytes:
    """
    AES-CBC 加密，Python 等效 Java 方法 a()

    :param body: 待加密字符串
    :param key: AES 密钥，长度必须 16/24/32
    :param iv: 初始化向量，长度必须 16
    :return: 加密后的字节数组
    """
    key = 'fd6b639dbcff0c2a1b03b389ec763c4b'
    iv = '77b07a672d57d64c'

    aes = AES.new(
        key=key.encode('utf-8'),
        mode=AES.MODE_CBC,
        iv=iv.encode('utf-8')
    )
    raw = pad(body.encode('utf-8'), 16)

    return aes.encrypt(raw)


def get_aid_cid(exec_url):
    """获取aid和cid"""
    session = requests.Session()
    bvid = exec_url.rsplit('/')[-1] or exec_url.rsplit('/')[-2]
    header = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
    }
    res = session.get(
        url="https://api.bilibili.com/x/player/pagelist?bvid={}&jsonp=jsonp".format(bvid),
        headers=header
    )
    cid = res.json()['data'][0]['cid']

    res = session.get(
        url="https://api.bilibili.com/x/web-interface/view?cid={}&bvid={}".format(cid, bvid),
        headers=header

    )
    res_json = res.json()
    aid = res_json['data']['aid']
    view_count = res_json['data']['stat']['view']
    duration = res_json['data']['duration']
    session.close()
    return aid, cid, view_count, duration


def generate_did() -> str:
    """生成 did (模拟 Android 设备 ID 算法)"""

    def create_random_mac(sep=":"):
        """随机生成 MAC 地址"""
        data_list = []
        for _ in range(6):
            part = "".join(random.sample("0123456789ABCDEF", 2))
            data_list.append(part)
        return sep.join(data_list)

    def gen_sn():
        """随机生成序列号 (10 位数字+字母)"""
        return "".join(random.sample("123456789" + string.ascii_lowercase, 10))

    def base64_encrypt(data_string):
        """自定义 base64 加密"""
        data_bytes = bytearray(data_string.encode("utf-8"))
        data_bytes[0] = data_bytes[0] ^ (len(data_bytes) & 0xFF)
        for i in range(1, len(data_bytes)):
            data_bytes[i] = (data_bytes[i - 1] ^ data_bytes[i]) & 0xFF
        res = base64.encodebytes(bytes(data_bytes))
        return res.strip().strip(b"==").decode("utf-8")

    # 组装 did 原始数据
    mac_string = create_random_mac(sep="")
    sn = gen_sn()
    prev_did = f"{mac_string}|||{sn}"

    # 返回加密后的 did
    return base64_encrypt(prev_did)
