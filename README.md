适用于清元优软URP（University Resource Planning）教务系统学生站

功能：监控教务系统页面，当有成绩更新时发送邮件进行提醒。

填写Grade-Watcher.py最后面的配置部分即可使用：

```
# 配置
    elaina = User(
        username='',  # 学号
        password='',  # 密码

        mail_sender='', # 发件人邮箱
        mail_sender_password='', # 邮箱 smtp 密钥
        mail_sender_host='smtp.163.com', # smtp 服务器，以 163 邮箱为例
        mail_sender_port='465', # smtp 服务器端口

        mail_receiver='',  # 收件人邮箱
        base_url='http://jwstudent.lnu.edu.cn' # 教务系统地址，本程序仅对本校做了适配，其它学校的可能要自行微调代码
    )
```

~~上完Python课一时兴起的产物，本校学生如需支持请提Issues。~~

2024.12.10 更新：重构代码，添加日志
