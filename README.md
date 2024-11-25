适用于URP教务系统学生站

功能：监控教务系统页面，当有成绩更新时发送邮件进行提醒。

填写Grade-Watcher.py最后面的配置部分即可使用：

```
# 配置
username='',  # 学号
password='',  # 教务系统密码
mail_sender='', # 发件人邮箱
mail_sender_password='', # 邮箱 smtp 服务密码
mail_sender_host='smtp.163.com', # smtp 服务器
mail_sender_port='465', # smtp 端口号
mail_receiver='',  # 收件人邮箱
base_url='' # 如用于同一系统的其它学校教务网站，代码可能需要进行一些适配
```

上完Python课一时兴起的产物，如需支持请提Issues。

涉及技术：验证码识别，登录持久化，解析成绩数据，smtp发送邮件，系统日志。
