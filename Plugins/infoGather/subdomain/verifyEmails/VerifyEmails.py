'''
在线验证邮箱真实性
'''

import random
import smtplib
from termcolor import cprint
import dns.resolver
import time
from queue import Queue
from threading import Thread

# 查询邮件服务器
def get_mailServer(server):
    print('查找[{}]邮箱服务器...'.format(server))
    try:
        answers = dns.resolver.query(server, 'MX')
        res = [str(rdata.exchange)[:-1] for rdata in answers]
        print('\t[{}]邮件服务器：{}'.format(server, res))
        return res
    except Exception as e:
        print('\t[error] : {}'.format(e.args))
        return []

# 判断邮箱是否存活
def checkEmail(mailServers, emails_queue, aliveEmails):
    try:
        mailServer = random.choice(mailServers)
        print('\t连接服务器:{}'.format(mailServer))
        s = smtplib.SMTP(mailServer, timeout=10)
    except Exception as e:
        print('\t[error] : {}'.format(e.args))
        return

    while not emails_queue.empty():
        email = emails_queue.get()
        num = emails_queue.qsize()
        try:
            helo = s.docmd('HELO chacuo.net')
            # print(helo)   # (250, b'Forcepoint email protection service')
            send_from = s.docmd('MAIL FROM:<test@test.test>')
            # print(send_from)  # (250, b'2.1.0 Ok')
            send_from = s.docmd('RCPT TO:<%s>' % email)
            # print(send_from)  # (550, b'5.1.1 Error: invalid recipients is found from 101.68.81.227') 或者 (250, b'2.1.5 Ok')
            if send_from[0] == 250 or send_from[0] == 451:
                # final_res[email] = True  # 存在
                cprint('\t[{}] [+] {}'.format(num, email), 'red')
                aliveEmails.append(email)
            elif send_from[0] == 550:
                # final_res[email] = False  # 不存在
                print('\t[{}] [-] {} 不存在'.format(num, email))
            elif send_from[0] == 503:
                cprint('\t[{}] [-] {} code = 503 重新连接邮件服务器{}'.format(num, email, mailServer))
                s.close()
                time.sleep(10)
                try:
                    s = smtplib.SMTP(mailServer, timeout=10)
                except Exception as e:
                    s.close()
                    time.sleep(10)
                    s = smtplib.SMTP(mailServer, timeout=10)
                helo = s.docmd('HELO chacuo.net')
                send_from = s.docmd('MAIL FROM:<test@test.test>')
                send_from = s.docmd('RCPT TO:<%s>' % email)
                if send_from[0] == 250 or send_from[0] == 451:
                    cprint('\t[{}] [+] {}'.format(num, email), 'red')
                    aliveEmails.append(email)
                elif send_from[0] == 550:
                    print('\t[{}] [-] {}'.format(num, email))
            else:
                # final_res[email] = None  # 未知
                print('\t[{}] [-] {} : {} : {}'.format(num, email, send_from[0], send_from))
        except Exception as e:
            print('\t[{}] [error] {} : {}'.format(num, email, e.args))
            s.close()
            try:
                s = smtplib.SMTP(mailServer, timeout=10)
            except Exception as e:
                s.close()
                time.sleep(10)
                s = smtplib.SMTP(mailServer, timeout=10)
    s.close()

def run(emails):
    Server_emails = {}
    aliveEmails = []    # 存活的emails

    for email in emails:
        name, server = email.split('@')
        if Server_emails.get(server):
            Server_emails[server].append(email)
        else:
            Server_emails[server] = [email]

    print(Server_emails)

    for server in Server_emails:
        mailServers = get_mailServer(server)
        if mailServers:
            emailsNums = len(Server_emails[server])
            emails_queue = Queue(-1)
            for email in Server_emails[server]:
                emails_queue.put(email)

            threads = []
            for i in range(5):
                t = Thread(target=checkEmail, args=(mailServers, emails_queue, aliveEmails))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

    return aliveEmails

def run_verifyEmails(emails):
    aliveEmails = run(emails)
    return aliveEmails

if __name__ == '__main__':
    emails = []
    with open('mail.txt', 'rt') as f:
        for each in f.readlines():
            emails.append(each.strip()+"@xxxxx.com")
    aliveEmails = run_verifyEmails(emails)
    print(aliveEmails)
    for aliveEmail in aliveEmails:
        print(aliveEmail)