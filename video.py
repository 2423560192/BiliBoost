import json
import re

import requests
from utils.util import logger


def get_response(url):
    """获取响应"""

    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'zh-CN,zh;q=0.9',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'priority': 'u=0, i',
        'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
    }

    response = requests.get('https://www.bilibili.com/video/BV1BSevzvEVA/', headers=headers)

    return response.text


def parse_data(resp_data):
    """解析数据"""
    pattern = r'window\.__INITIAL_STATE__\s*=\s*(\{.*\});'
    match = re.search(pattern, resp_data, re.S)
    if match:
        state_str = match.group(1)
        try:
            return json.loads(state_str)['videoData']
        except:
            return False


def get_detail_data(video_data):
    """获取详细数据"""
    title = video_data['title']  # 标题
    name = video_data['owner']['name']  # 作者
    view = video_data['stat']['view']  # 播放量
    face = video_data['pic']  # 封面
    logger.info("标题： %s" % title)
    logger.info("作者： %s" % name)
    logger.info("播放量： %s" % view)
    logger.info("封面： %s" % face)
    return title, name, view, face


def main(url):
    """主程序"""
    resp = get_response(url)
    # 解析数据
    video_data = parse_data(resp)
    if not video_data:
        return False
    # 获取视频详细数据
    detail_data = get_detail_data(video_data)
    return detail_data

# if __name__ == '__main__':
#     url = 'bilibili.com/video/BV1BSevzvEVA/'
#     main(url)
