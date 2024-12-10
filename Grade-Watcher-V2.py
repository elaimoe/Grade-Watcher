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
sleep_time = 60  # 默认每轮请求间隔时间，单位为秒，最小建议为 60，过高速度可能会导致封禁


class User:
    def __init__(self, username, password, mail_sender, mail_sender_password, mail_sender_host,
                 mail_sender_port, mail_receiver, base_url):
        self.username = username
        self.password = password
        self.password_encrypt = (hashlib.md5((self.password+"{Urp602019}").encode("utf-8")).hexdigest() +
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
