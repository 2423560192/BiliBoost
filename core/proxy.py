import threading
import random

import requests

from config.config import get_proxy_config


class IpService:
    def __init__(self):
        self.url = get_proxy_config()['api_url']

    def get_ip(self):
        """获取ip"""
        response = requests.get(self.url)
        lst = response.text.split('\n')
        return random.choice(lst)


if __name__ == '__main__':
    proxy = IpService()
    proxy.get_ip()
