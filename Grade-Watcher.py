import hashlib
import io
import json
import logging
import re
import smtplib
from time import sleep

import numpy as np
import paddleocr  # 需要执行 pip install paddlepaddle paddleocr 以安装
import requests
from PIL import Image
from bs4 import BeautifulSoup

from email.mime.text import MIMEText

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # 测试时 INFO 可改成 DEBUG
sleep_time = 2  # 默认每轮请求间隔时间，单位为秒，最小建议为 60，过高速度可能会导致封禁


class User:
    def __init__(self, username, password, mail_sender, mail_sender_password, mail_sender_host,
                 mail_sender_port, mail_receiver, base_url):
        self.username = username
        self.password = password
        self.password_encrypt = (self.encrypt(self.password) +
                                 "*" + hashlib.md5(self.password.encode("utf-8")).hexdigest())
        self.mail_sender = mail_sender
        self.mail_sender_password = mail_sender_password
        self.mail_sender_host = mail_sender_host
        self.mail_sender_port = mail_sender_port
        self.mail_receiver = mail_receiver
        self.base_url = base_url

        # 其它信息
        self.headers_user_agent = {'User-Agent': 'Grade-Watcher (+https://github.com/elaimoe/grade-watcher)'}
        self.cookie = None
        self.grade = None

    def __str__(self):  # 显示用户信息
        return (f"User(username={self.username}, "
                f"password={self.password}, "
                f"password_encrypt={self.password_encrypt}, "
                f"mail_sender={self.mail_sender}, "
                f"mail_sender_password={self.mail_sender_password}, "
                f"mail_sender_host={self.mail_sender_host}, "
                f"mail_sender_port={self.mail_sender_port}, "
                f"mail_receiver={self.mail_receiver}, "
                f"base_url={self.base_url}, "
                f"headers_user_agent={self.headers_user_agent}, "
                f"cookie={self.cookie}, "
                f"grade={self.grade})")

    def __repr__(self):
        return self.__str__()

    @staticmethod  # 翻译自 md5.min.js
    def encrypt(str_passwd):
        def md5_rotate_left(l_value, i_shift_bits):
            return (l_value << i_shift_bits) | (l_value >> (32 - i_shift_bits))

        def md5_add_unsigned(l_x, l_y):
            l_x4 = l_x & 0x40000000
            l_y4 = l_y & 0x40000000
            l_x8 = l_x & 0x80000000
            l_y8 = l_y & 0x80000000
            l_result = (l_x & 0x3FFFFFFF) + (l_y & 0x3FFFFFFF)
            if l_x4 & l_y4:
                return l_result ^ 0x80000000 ^ l_x8 ^ l_y8
            if l_x4 | l_y4:
                if l_result & 0x40000000:
                    return l_result ^ 0xC0000000 ^ l_x8 ^ l_y8
                else:
                    return l_result ^ 0x40000000 ^ l_x8 ^ l_y8
            else:
                return l_result ^ l_x8 ^ l_y8

        def md5_f(x, y, z):
            return (x & y) | (~x & z)

        def md5_g(x, y, z):
            return (x & z) | (y & ~z)

        def md5_h(x, y, z):
            return x ^ y ^ z

        def md5_i(x, y, z):
            return y ^ (x | ~z)

        def md5_ff(a, b, c, d, x, s, ac):
            a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_f(b, c, d), x), ac))
            return md5_add_unsigned(md5_rotate_left(a, s), b)

        def md5_gg(a, b, c, d, x, s, ac):
            a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_g(b, c, d), x), ac))
            return md5_add_unsigned(md5_rotate_left(a, s), b)

        def md5_hh(a, b, c, d, x, s, ac):
            a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_h(b, c, d), x), ac))
            return md5_add_unsigned(md5_rotate_left(a, s), b)

        def md5_ii(a, b, c, d, x, s, ac):
            a = md5_add_unsigned(a, md5_add_unsigned(md5_add_unsigned(md5_i(b, c, d), x), ac))
            return md5_add_unsigned(md5_rotate_left(a, s), b)

        def md5_convert_to_word_array(string):
            l_message_length = len(string)
            l_number_of_words_temp1 = l_message_length + 8
            l_number_of_words_temp2 = (l_number_of_words_temp1 - (l_number_of_words_temp1 % 64)) // 64
            l_number_of_words = (l_number_of_words_temp2 + 1) * 16
            l_word_array = [0] * l_number_of_words
            l_byte_position = 0
            l_byte_count = 0

            while l_byte_count < l_message_length:
                l_word_count = l_byte_count // 4
                l_byte_position = (l_byte_count % 4) * 8
                l_word_array[l_word_count] |= ord(string[l_byte_count]) << l_byte_position
                l_byte_count += 1

            l_word_count = l_byte_count // 4
            l_byte_position = (l_byte_count % 4) * 8
            l_word_array[l_word_count] |= 0x80 << l_byte_position
            l_word_array[l_number_of_words - 2] = l_message_length << 3
            l_word_array[l_number_of_words - 1] = l_message_length >> 29

            return l_word_array

        def md5_word_to_hex(l_value):
            word_to_hex_value = ""
            for l_count in range(4):
                l_byte = (l_value >> (l_count * 8)) & 255
                word_to_hex_value += f"{l_byte:02x}"
            return word_to_hex_value

        def md5_utf8_encode(string):
            return string.encode('utf-8')

        def hex_md5(string, ver):
            S11, S12, S13, S14 = 7, 12, 17, 22
            S21, S22, S23, S24 = 5, 9, 14, 20
            S31, S32, S33, S34 = 4, 11, 16, 23
            S41, S42, S43, S44 = 6, 10, 15, 21

            string = md5_utf8_encode(string + ("" if ver == "1.8" else "{Urp602019}")).decode('utf-8')
            x = md5_convert_to_word_array(string)
            a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

            for k in range(0, len(x), 16):
                AA, BB, CC, DD = a, b, c, d

                a = md5_ff(a, b, c, d, x[k + 0], S11, 0xD76AA478)
                d = md5_ff(d, a, b, c, x[k + 1], S12, 0xE8C7B756)
                c = md5_ff(c, d, a, b, x[k + 2], S13, 0x242070DB)
                b = md5_ff(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE)
                a = md5_ff(a, b, c, d, x[k + 4], S11, 0xF57C0FAF)
                d = md5_ff(d, a, b, c, x[k + 5], S12, 0x4787C62A)
                c = md5_ff(c, d, a, b, x[k + 6], S13, 0xA8304613)
                b = md5_ff(b, c, d, a, x[k + 7], S14, 0xFD469501)
                a = md5_ff(a, b, c, d, x[k + 8], S11, 0x698098D8)
                d = md5_ff(d, a, b, c, x[k + 9], S12, 0x8B44F7AF)
                c = md5_ff(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1)
                b = md5_ff(b, c, d, a, x[k + 11], S14, 0x895CD7BE)
                a = md5_ff(a, b, c, d, x[k + 12], S11, 0x6B901122)
                d = md5_ff(d, a, b, c, x[k + 13], S12, 0xFD987193)
                c = md5_ff(c, d, a, b, x[k + 14], S13, 0xA679438E)
                b = md5_ff(b, c, d, a, x[k + 15], S14, 0x49B40821)

                a = md5_gg(a, b, c, d, x[k + 1], S21, 0xF61E2562)
                d = md5_gg(d, a, b, c, x[k + 6], S22, 0xC040B340)
                c = md5_gg(c, d, a, b, x[k + 11], S23, 0x265E5A51)
                b = md5_gg(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA)
                a = md5_gg(a, b, c, d, x[k + 5], S21, 0xD62F105D)
                d = md5_gg(d, a, b, c, x[k + 10], S22, 0x2441453)
                c = md5_gg(c, d, a, b, x[k + 15], S23, 0xD8A1E681)
                b = md5_gg(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8)
                a = md5_gg(a, b, c, d, x[k + 9], S21, 0x21E1CDE6)
                d = md5_gg(d, a, b, c, x[k + 14], S22, 0xC33707D6)
                c = md5_gg(c, d, a, b, x[k + 3], S23, 0xF4D50D87)
                b = md5_gg(b, c, d, a, x[k + 8], S24, 0x455A14ED)
                a = md5_gg(a, b, c, d, x[k + 13], S21, 0xA9E3E905)
                d = md5_gg(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8)
                c = md5_gg(c, d, a, b, x[k + 7], S23, 0x676F02D9)
                b = md5_gg(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A)

                a = md5_hh(a, b, c, d, x[k + 5], S31, 0xFFFA3942)
                d = md5_hh(d, a, b, c, x[k + 8], S32, 0x8771F681)
                c = md5_hh(c, d, a, b, x[k + 11], S33, 0x6D9D6122)
                b = md5_hh(b, c, d, a, x[k + 14], S34, 0xFDE5380C)
                a = md5_hh(a, b, c, d, x[k + 1], S31, 0xA4BEEA44)
                d = md5_hh(d, a, b, c, x[k + 4], S32, 0x4BDECFA9)
                c = md5_hh(c, d, a, b, x[k + 7], S33, 0xF6BB4B60)
                b = md5_hh(b, c, d, a, x[k + 10], S34, 0xBEBFBC70)
                a = md5_hh(a, b, c, d, x[k + 13], S31, 0x289B7EC6)
                d = md5_hh(d, a, b, c, x[k + 0], S32, 0xEAA127FA)
                c = md5_hh(c, d, a, b, x[k + 3], S33, 0xD4EF3085)
                b = md5_hh(b, c, d, a, x[k + 6], S34, 0x4881D05)
                a = md5_hh(a, b, c, d, x[k + 9], S31, 0xD9D4D039)
                d = md5_hh(d, a, b, c, x[k + 12], S32, 0xE6DB99E5)
                c = md5_hh(c, d, a, b, x[k + 15], S33, 0x1FA27CF8)
                b = md5_hh(b, c, d, a, x[k + 2], S34, 0xC4AC5665)

                a = md5_ii(a, b, c, d, x[k + 0], S41, 0xF4292244)
                d = md5_ii(d, a, b, c, x[k + 7], S42, 0x432AFF97)
                c = md5_ii(c, d, a, b, x[k + 14], S43, 0xAB9423A7)
                b = md5_ii(b, c, d, a, x[k + 5], S44, 0xFC93A039)
                a = md5_ii(a, b, c, d, x[k + 12], S41, 0x655B59C3)
                d = md5_ii(d, a, b, c, x[k + 3], S42, 0x8F0CCC92)
                c = md5_ii(c, d, a, b, x[k + 10], S43, 0xFFEFF47D)
                b = md5_ii(b, c, d, a, x[k + 1], S44, 0x85845DD1)
                a = md5_ii(a, b, c, d, x[k + 8], S41, 0x6FA87E4F)
                d = md5_ii(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0)
                c = md5_ii(c, d, a, b, x[k + 6], S43, 0xA3014314)
                b = md5_ii(b, c, d, a, x[k + 13], S44, 0x4E0811A1)
                a = md5_ii(a, b, c, d, x[k + 4], S41, 0xF7537E82)
                d = md5_ii(d, a, b, c, x[k + 11], S42, 0xBD3AF235)
                c = md5_ii(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB)
                b = md5_ii(b, c, d, a, x[k + 9], S44, 0xEB86D391)

                a = md5_add_unsigned(a, AA)
                b = md5_add_unsigned(b, BB)
                c = md5_add_unsigned(c, CC)
                d = md5_add_unsigned(d, DD)

            return (md5_word_to_hex(a) + md5_word_to_hex(b) + md5_word_to_hex(c) + md5_word_to_hex(d)).lower()

        return hex_md5(str_passwd, '')


class Login:
    def __init__(self, user, retries=5):
        self.user = user
        self.retries = retries
        self.session = requests.Session()
        self.ocr = paddleocr.PaddleOCR(use_angle_cls=True, lang="ch", show_log=False).ocr

    def recognize_captcha(self):
        # 获取验证码
        captcha_url = f"{self.user.base_url}/img/captcha.jpg"
        for i in range(self.retries + 10):  # 验证码识别容易出错，需要多识别几次
            try:
                response = self.session.get(captcha_url)
                response.raise_for_status()
                image = Image.open(io.BytesIO(response.content))
                # image.save("captcha.jpg")  # 保存验证码图片
                result = self.ocr(np.array(image))

                if result and len(result) > 0:
                    if isinstance(result[0], list) and len(result[0]) > 0:
                        if isinstance(result[0][0], list) and len(result[0][0]) > 1:
                            captcha = result[0][0][1][0]
                            logger.info(f"验证码识别成功，结果为: {captcha}")
                            if re.match(r'^[a-zA-Z0-9]{4}$', captcha):
                                # 校验识别结果是否为 4 位字母或数字
                                logger.info(f"验证码校验成功")
                            else:
                                logger.warning("验证码校验失败，正在重试")
                                continue
                            return captcha  # 返回识别的文本
                logger.warning(f"验证码识别失败第{i + 1}次")

            except requests.RequestException as e:
                logger.error(f"验证码请求失败: {e}")
            except Exception as e:
                logger.error(f"验证码处理失败: {e}")

    def __call__(self):
        for i in range(self.retries):
            try:
                sleep(sleep_time)
                # 获取登录页面
                response = self.session.get(f"{self.user.base_url}/login")
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                token_value = soup.find('input', {'id': 'tokenValue'})['value']

                # 获取并识别验证码
                captcha_code = self.recognize_captcha()

                # 准备登录数据
                login_data = {
                    'j_username': self.user.username,
                    'j_password': self.user.password_encrypt,
                    'j_captcha': captcha_code,
                    'tokenValue': token_value
                }
                logger.debug(f"登录数据: {login_data}")

                # 发送登录请求
                login_url = f"{self.user.base_url}/j_spring_security_check"
                response = self.session.post(login_url, data=login_data, headers=self.user.headers_user_agent)
                response.raise_for_status()

                # 错误处理
                if "验证码错误" in response.text:
                    logger.warning(f"登录失败第{i + 1}次，验证码识别错误")
                elif "错误" in response.text:
                    logger.warning(f"登录失败第{i + 1}次，用户名或密码错误")
                else:
                    logger.info("登录成功")
                    cookies = self.session.cookies.get_dict()
                    logger.info(f"cookie: {cookies}")
                    self.user.cookie = cookies
                    return

            except requests.RequestException as e:
                logger.error(f"登录请求失败: {e}")
            except Exception as e:
                logger.error(f"登录过程出现错误: {e}")


class Fetcher:
    def __init__(self, user, retries=5):
        self.user = user
        self.retries = retries
        self.session = requests.Session()

    def get_web(self, url):
        # 发送 get 请求，获取页面
        for i in range(self.retries):
            try:
                sleep(sleep_time)
                logger.debug(f"获取页面: {url}")
                logger.debug(f"cookie: {self.user.cookie}")
                response = self.session.get(url, headers=self.user.headers_user_agent, cookies=self.user.cookie)
                response.raise_for_status()
                return BeautifulSoup(response.text, 'lxml')
            except requests.RequestException as e:
                logger.error(f"获取页面失败: {e}")

    @staticmethod
    def show(grade):
        # 解析 json 格式成绩单数据
        try:
            parsed_data = json.loads(grade)
        except json.JSONDecodeError:
            logger.critical("JSON解析错误")
            raise "JSON解析错误"

        for item in parsed_data:
            course_list = item.get("list", [])
            result = ""
            for course in course_list:
                course_name = course.get("courseName")
                course_grade = course.get("courseScore")
                result += f"课程: {course_name}, 成绩: {course_grade}\n"

            logger.debug(f"本次遍历获取得到{result}")
            return result

    def __call__(self):
        try:
            url = f"{self.user.base_url}/student/integratedQuery/scoreQuery/thisTermScores/index"
            html = self.get_web(url)
            regex = r"var\s+url\s*=\s*['\"]([^'\"]*)['\"]"  # 正则匹配得到 url
            match = re.search(regex, str(html))
            if match:
                match_url = self.user.base_url + match.group(1)
                logger.debug(f"成绩单页面链接: {match_url}")
            else:
                logger.critical("链接匹配错误")
                raise "链接匹配错误"

            data = str(self.get_web(match_url))  # 获取成绩单页面

            # 存储成绩单数据
            self.user.grade = self.show(data.replace('<html><body><p>', '').replace('</p></body></html>', ''))
            return

        except ValueError as e:
            logger.error(f"获取成绩数据失败: {e}")


class Mailer:
    def __init__(self, user, retries=5):
        self.user = user
        self.retries = retries

    def __call__(self, subject, message):
        for i in range(self.retries):
            sleep(sleep_time)
            try:
                msg = MIMEText(message, 'plain', _charset="utf-8")  # 创建 MIME 类型消息
                msg["Subject"] = subject

                # 发送邮件
                with smtplib.SMTP_SSL(host=self.user.mail_sender_host, port=self.user.mail_sender_port) as smtp:
                    smtp.login(user=self.user.mail_sender, password=self.user.mail_sender_password)
                    smtp.sendmail(from_addr=self.user.mail_sender,
                                  to_addrs=self.user.mail_receiver.split(','), msg=msg.as_string())
                logger.info("邮件发送成功")
                return

            except smtplib.SMTPException as e:
                logger.warning(f"邮件发送失败第{i + 1}次: {str(e)}")
            except Exception as e:
                logger.error(f"邮件发送过程中出现错误: {str(e)}")


class Monitor:
    def __init__(self, user):
        self.user = user
        self.mail_sender = Mailer(user)
        self.login = Login(user)
        self.fetcher = Fetcher(user)

    def initialize_monitoring(self):
        try:
            self.login()
            self.fetcher()
            self.mail_sender("监控程序开始运行", self.user.grade)
            logger.info("初始化成功，监控程序开始运行")
        except ValueError as e:
            logger.critical(f"初始化失败: {str(e)}")
            raise f"初始化失败: {str(e)}"

    def start_monitoring(self, retries=20):
        self.initialize_monitoring()  # 先试运行
        current_grade = self.user.grade
        for j in range(retries):
            if j != 0:  # 第一次循环不执行，以便实现重新登录
                self.login()
            try:
                while True:
                    self.fetcher()
                    if self.user.grade != current_grade:  # 比较更新
                        current_grade = self.user.grade
                        logger.info("更新成功\n" + current_grade)
                        self.mail_sender("更新成功！请进入教务系统查看最新成绩单\n", current_grade)
                    else:
                        logger.info("无更新")
                    sleep(sleep_time)

            except ValueError as e:
                logger.error(f"{str(e)} 未知错误，大概率是cookie失效了，此为第{j + 1}/{retries}个cookie")
                self.mail_sender("监控程序错误", f"未知错误，大概率是cookie失效了，此为第{j + 1}/{retries}个cookie")

        logger.info("监控程序结束")
        self.mail_sender("监控程序结束", "监控程序结束")


if __name__ == '__main__':
    elaina = User(
        username='',  # 学号
        password='',  # 密码

        mail_sender='', # 发件人邮箱
        mail_sender_password='', # 邮箱 smtp 密钥
        mail_sender_host='smtp.163.com', # smtp 服务器，以 163 邮箱为例
        mail_sender_port='465', # smtp 端口

        mail_receiver='',  # 收件人邮箱
        base_url='http://jwstudent.lnu.edu.cn' # 教务系统地址
    )

    logger.info(elaina)
    monitor = Monitor(elaina)
    # monitor.initialize_monitoring() # 测试
    monitor.start_monitoring()
