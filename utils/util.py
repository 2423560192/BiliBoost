import os
import logging
import base64

from Crypto.Cipher import AES


def query_to_dict(s):
    return {item.split('=')[0]: item.split('=')[1] for item in s.split('&')}


def header_str_to_dict(header_str):
    res = [item for item in
           header_str.split('\n')]
    res = res[1:len(res) - 1]
    d = {item.split('\t')[0]: item.split('\t')[1] for item in res}
    return d


def pad_data(data):
    # 计算需要填充的字节数
    pad_len = AES.block_size - (len(data) % AES.block_size)
    # 使用填充字节进行填充
    padding = bytes([pad_len] * pad_len)
    padded_data = data + padding
    return padded_data


def encrypt_data(password):
    # 创建 AES 密码对象
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # 密钥（16 字节）
    key = b'6d6656a37cdb7977c10f6d83cab168e9'
    # 初始化向量（16 字节）
    iv = b'0000000000000000'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 填充数据
    padded_data = pad_data(password.encode('utf-8'))
    # 加密数据
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')


log_config = {
    'format': '%(asctime)s %(levelname)s [%(filename)s %(funcName)s line:%(lineno)d]: %(message)s',
    'level': int(os.getenv('LOG_LEVEL', logging.INFO)),
    'datefmt': None,
}


class Log(object):
    """
        Log Wrapper. Usage:
        >>> logger = Log(filename='app.log').get_logger()
        >>> logger.warn('This is warning')
        >>> logger.info('This is info')
    """

    def __init__(self):
        logging.basicConfig(**log_config)

    @staticmethod
    def get_logger(log_name=None):
        logger = logging.getLogger(log_name)
        return logger


logger = Log().get_logger()
