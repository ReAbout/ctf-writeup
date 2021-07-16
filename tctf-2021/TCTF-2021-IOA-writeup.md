# TCTF/0CTF 2021 IOA Writeup

## 0x00 前言
比赛时候有事划水，感觉这道题很适合对SSL VPN安全进行理解学习，因此复现分析一遍。      
参考：https://bestwing.me/2021-TCTF-RV-Writeup.html    

## 0x01 预备知识


## 0x02 题目

- [题目附件docker](./file/sslvpn_5fb7850841484a7034f3bdfa97f69be0.tar.gz)   
> PS：需要特权参数启动，要不设备会有功能无法加载报错。  

``` 
docker build --tag sslvpn:latest .
docker run --privileged --name 0ctf-sslvpn -p 4443:443 -d sslvpn:latest
```