import hashlib
import random
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from urllib import parse
import uuid
from datetime import datetime

import requests

from core.proxy import IpService
from core.parms import get_xw, get_buvid, get_device_id, get_fp_local, get_session_id, get_aid_cid, \
    generate_did, get_sign, aes_encrypt
from utils.util import logger




class BilibiliSpider:
    def __init__(self, url):
        self.session = requests.Session()
        self.url = url
        buvid = get_buvid()  # buvid生成
        device_id = get_device_id()  # 生成device_id
        fp_local = get_fp_local(buvid)  # 生成fp_local
        session_id = get_session_id()  # 生成session_id
        self.headers = {
            "Host": "api.bilibili.com",
            "buvid": buvid,
            "device-id": device_id,
            "fp_local": fp_local,
            "fp_remote": fp_local,
            "session_id": session_id,
            "env": "prod",
            "app-key": "android",
            "user-agent": "Mozilla/5.0 BiliDroid/6.24.0 (bbcallen@gmail.com) os/android model/Pixel 2 XL mobi_app/android build/6240300 channel/xxl_gdt_wm_253 innerVer/6240300 osVer/11 network/2",
            "bili-bridge-engine": "cronet",
            "content-type": "application/octet-stream"  # 需要修改
        }
        self.session.headers.update(self.headers)
        self.aid, self.cid, self.view_count, self.duration = get_aid_cid(self.url)
        self.ip = IpService().get_ip()
        logger.info("当前采用ip：%s" % self.ip)

        self.proxies = {
            "http": self.ip,
            "https": self.ip,  # 注意：很多 HTTP 代理可以同时代理 HTTPS（通过 CONNECT）
        }
        self.start_ts = None

    def get_params(self, aid, cid):
        """生成请求体"""
        self.start_ts = int(time.time())
        did = generate_did()
        logger.info("did: %s" % did)
        param = {
            "aid": aid,
            "auto_play": "0",
            "build": "6240300",
            "cid": cid,
            "did": did,
            "epid": "",
            "from_spmid": "tm.recommend.0.0",
            "ftime": self.start_ts - random.randint(100, 5000),
            "lv": "0",
            "mid": "0",
            "mobi_app": "android",
            "part": "0",
            "sid": "0",
            "spmid": "main.ugc-video-detail-vertical.0.0",
            "stime": self.start_ts,
            "sub_type": "0",
            "type": "3",
        }
        # 转成 URL 查询参数字符串
        param_str = parse.urlencode(param)
        # 加密获取sign
        sign = get_sign(param_str)
        logger.info("sign: %s", sign)
        # 再参数后面加上sign
        param_str += '&sign=' + sign
        body = aes_encrypt(param_str)
        return body

    def get_click_resp(self, data):
        url = "https://api.bilibili.com/x/report/click/android2"
        resp = self.session.post(url, data=data, proxies=self.proxies)
        return resp.text

    def click_req(self):
        """click请求"""
        # 生成请求体
        params = self.get_params(self.aid, self.cid)
        logger.info("params: %s" % params)
        # 发出请求
        resp = self.get_click_resp(params)
        logger.info("resp: %s" % resp)
        return resp

    def get_heart_resp_first(self, session):
        """心跳包请求"""
        self.session.headers.update({'content-type': 'application/x-www-form-urlencoded; charset=utf-8'})
        data = {
            'actual_played_time': '0',  # 实际播放时长（秒），包括暂停/切后台等累计到的播放
            'aid': self.aid,  # 视频 av 号（稿件 id，字符串形式）
            'appkey': '1d8b6e7d45233436',  # 固定 appkey，用于签名校验
            'auto_play': '0',  # 是否自动播放：0=否，1=是
            'build': '6240300',  # 客户端构建号（版本标识，6240300 对应 6.24.0）
            'c_locale': 'zh-Hans_CN',  # 客户端语言环境（简体中文-中国）
            'channel': 'xxl_gdt_wm_253',  # 渠道号（安装来源/推广渠道标识）
            'cid': self.cid,  # 视频 cid（内容分 P 的唯一 ID）
            'epid': '0',  # 番剧/剧集 ID，普通视频为 0
            'epid_status': '',  # 番剧相关的额外字段（普通视频为空）
            'from': '6',  # 播放来源场景（6=推荐流等）
            'from_spmid': 'tm.recommend.0.0',  # 来源埋点 ID（推荐页、搜索、动态等位置标识）
            'last_play_progress_time': '0',  # 上次播放进度（秒），断点续播用
            'list_play_time': '0',  # 播放列表累计时长（通常为 0，playlist 时有用）
            'max_play_progress_time': '0',  # 本次最大播放进度（秒，防止快退刷时长）
            'mid': '0',  # 用户 mid（未登录时为 0）
            'miniplayer_play_time': '0',  # 小窗/悬浮窗播放时长
            'mobi_app': 'android',  # 客户端平台标识（android/ios/web）
            'network_type': '1',  # 网络类型：1=WiFi，2=移动网络
            'paused_time': '0',  # 暂停时长累计
            'platform': 'android',  # 运行平台
            'play_status': '0',  # 播放状态：0=播放中，1=暂停
            'play_type': '1',  # 播放类型：1=普通播放，其他可能对应投屏/下载等
            'played_time': '0',  # 播放进度（秒），本次心跳上报的时长
            'quality': '64',  # 清晰度代码（64=720P，其它如 16=360P，32=480P）
            's_locale': 'zh-Hans_CN',  # 系统语言环境
            'session': session,  # 会话 ID（播放 session 标识，用于区分一次播放过程）
            'sid': '0',  # 番剧 sid（剧集分区 ID），普通视频为 0
            'spmid': 'main.ugc-video-detail-vertical.0.0',  # 页面埋点 ID，标识播放入口
            'start_ts': '0',  # 播放开始时间戳（Unix 秒），首次心跳时可能为 0
            'statistics': '{"appId":1,"platform":3,"version":"6.24.0","abtest":""}',
            # 客户端统计信息（包含 appId、平台、版本、AB 实验信息）
            'sub_type': '0',  # 子类型（0=普通视频，番剧/合集可能有别的值）
            'total_time': '0',  # 播放总时长累计（秒），用于记录观看了多久
            'ts': self.start_ts,  # 当前上报时间戳（Unix 秒，参与 sign 签名）
            'type': '3',  # 视频类型：3=ugc 视频，2=番剧等
            'user_status': '0',  # 用户状态字段（可能是登录/会员相关，未登录时为 0）
            'video_duration': self.duration,  # 视频总时长（秒）
        }

        sign = self.get_sign(data)  # 获取sign值
        data['sign'] = sign

        response = self.session.post('https://api.bilibili.com/x/report/heartbeat/mobile', data=data,
                                     proxies=self.proxies)

        return response.text

    def get_heart_resp_end(self, session):
        """心跳包请求"""
        self.session.headers.update({'content-type': 'application/x-www-form-urlencoded; charset=utf-8'})
        end_ts = int(time.time())
        data = {
            'actual_played_time': end_ts - self.start_ts,
            'aid': self.aid,
            'appkey': '1d8b6e7d45233436',
            'auto_play': '0',
            'build': '6240300',
            'c_locale': 'zh-Hans_CN',
            'channel': 'xxl_gdt_wm_253',
            'cid': self.cid,
            'epid': '0',
            'epid_status': '',
            'from': '6',
            'from_spmid': 'tm.recommend.0.0',
            'last_play_progress_time': end_ts - self.start_ts - 1,
            'list_play_time': '0',
            'max_play_progress_time': end_ts - self.start_ts - 1,
            'mid': '0',
            'miniplayer_play_time': '0',
            'mobi_app': 'android',
            'network_type': '1',
            'paused_time': '0',  # 可以置 0，避免异常
            'platform': 'android',
            'play_status': '0',
            'play_type': '1',
            'played_time': end_ts - self.start_ts,
            'quality': '64',
            's_locale': 'zh-Hans_CN',
            'session': session,
            'sid': '0',
            'spmid': 'main.ugc-video-detail-vertical.0.0',
            'start_ts': self.start_ts,  # 与首包时间对齐
            'statistics': '{"appId":1,"platform":3,"version":"6.24.0","abtest":""}',
            'sub_type': '0',
            'total_time': end_ts - self.start_ts,  # 播放总耗时
            'ts': end_ts,  # 当前上报时间
            'type': '3',
            'user_status': '0',
            'video_duration': self.duration,
        }

        sign = self.get_sign(data)  # 获取sign值
        data['sign'] = sign

        response = self.session.post('https://api.bilibili.com/x/report/heartbeat/mobile', data=data,
                                     proxies=self.proxies)

        return response.text

    def get_session(self):
        """获取session的值"""
        arg0 = "1748437928237596335"
        hash_object = hashlib.sha1()
        hash_object.update(arg0.encode('utf-8'))
        session = hash_object.hexdigest()
        return session

    def get_sign(self, data):
        """获取sign值"""
        s = parse.urlencode(data)
        logger.info("s: %s", s)
        obj = hashlib.md5()
        obj.update(
            s.encode(
                'utf-8'))
        obj.update("560c52cc".encode('utf-8'))
        obj.update("d288fed0".encode('utf-8'))
        obj.update("45859ed1".encode('utf-8'))
        obj.update("8bffd973".encode('utf-8'))
        sign = obj.hexdigest()
        logger.info("sign: %s", sign)
        return sign

    def heart_req(self):
        """心跳包请求"""
        session = self.get_session()  # 获取session
        logger.info("session: %s" % session)

        resp = self.get_heart_resp_first(session)
        logger.info("resp: %s" % resp)
        # 开始播放
        logger.info('当前播放时长： %s s' % self.duration)
        time.sleep(self.duration + random.randint(1, 5))
        # time.sleep(random.randint(1, 5))
        resp = self.get_heart_resp_end(session)
        logger.info("resp: %s" % resp)

    def run(self):
        logger.info('当前url： %s' % self.url)
        self.aid, self.cid, self.view_count, self.duration = get_aid_cid(self.url)
        logger.info("当前播放量: %s" % self.view_count)
        # 发送click请求
        self.click_req()
        # 发出心跳包
        self.heart_req()
        self.aid, self.cid, self.view_count, self.duration = get_aid_cid(self.url)
        logger.info("播放完成")
        logger.info("当前播放量: %s" % self.view_count)
        logger.info("-----------------------------------------")


# if __name__ == '__main__':
#     spider = BilibiliSpider()
#     spider.main()
def run_bili(url):
    bili = BilibiliSpider(url)
    bili.run()
