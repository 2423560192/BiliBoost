import threading
import random

import requests


class IpService:
    def __init__(self):
        self.url = 'http://api2.xkdaili.com/tools/XApi.ashx?apikey=XK69862370B1CA650629&qty=100&format=txt&split=0&sign=87a269171ead05ba5185eba8eb5a162a&time=3'

    def get_ip(self):
        """获取ip"""
        response = requests.get(self.url)
        lst = response.text.split('\n')
        return random.choice(lst)


if __name__ == '__main__':
    proxy = IpService()
    proxy.get_ip()
