# 水泽-信息收集自动化工具

[![GitHub release](https://img.shields.io/github/release/0x727/ShuiZe_0x727.svg)](https://github.com/0x727/ShuiZe_0x727/releases)

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

## 0x01 介绍

作者：[Ske](https://github.com/SkewwG)

团队：[0x727](https://github.com/0x727)，未来一段时间将陆续开源工具，地址：https://github.com/0x727

定位：协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点

语言：python3开发

功能：一条龙服务，只需要输入根域名即可全方位收集相关资产，并检测漏洞。也可以输入多个域名、C段IP等，具体案例见下文。

调用：脚本借用了ksubdomain爆破子域名和theHarvester收集邮箱，感谢ksubdomain和theHarvester作者

## 0x02 安装

为了避免踩坑,建议安装在如下环境中

* 当前用户对该目录有写权限，不然扫描结果无法生成。root权限即可
* Python环境必须是3.7以上，因为使用了异步。建议VPS环境是ubuntu20，默认是python3.8。安装模块的时候切记不要走豆瓣的源
* 在配置文件iniFile/config.ini里加入api（fofa、shodan、github、virustotal）

```
chmod 777 build.sh
./build.sh
```

![image-20210728153419131](imgs/image-20210728153419131.png)

`python3 ShuiZe.py -h`

![image-20210728154929084](imgs/image-20210728154929084.png)


### docker运行ShuiZe

较多人反馈安装的时候会出现各种报错，新增通过docker运行ShuiZe

通过下面的命令安装docker，然后拉取python3.8的容器，再git clone水泽后，运行docker_build.sh即可。

```
apt install docker.io
docker pull yankovg/python3.8.2-ubuntu18.04
docker run -itd yankovg/python3.8.2-ubuntu18.04 bash
docker exec -it docker的ID /bin/bash
apt-get update
apt install git --fix-missing
apt install vim
rm /usr/bin/python3
ln -s /usr/local/bin/python3.8 /usr/bin/python3
python3 -m pip install --upgrade pip
git clone https://github.com/0x727/ShuiZe_0x727.git
chmod 777 docker_build.sh
./docker_build.sh
```

## 0x03 效果展示

备案反查顶级域名

![image-20210728155358378](imgs/image-20210728155358378.png)

不是泛解析，调用ksubdomain爆破子域名

![image-20210728155541501](imgs/image-20210728155541501-7458943.png)

theHarvest获取邮箱

![image-20210728161507035](imgs/image-20210728161507035.png)

![image-20210728163216047](imgs/image-20210728163216047.png)

第三方数据接口 -> 获取子域名

![image-20210728160705706](imgs/image-20210728160705706.png)

github -> 从github获取子域名，并把查询结果保存到txt，并匹配关键字获取敏感信息

![image-20210728161022348](imgs/image-20210728161022348.png)

百度和必应爬虫

![image-20210728161117459](imgs/image-20210728161117459.png)

证书

![image-20210728161711534](imgs/image-20210728161711534.png)

子域名友链

![image-20210728161339208](imgs/image-20210728161339208.png)

解析子域名A记录,检测是否CDN和整理C段的IP

![image-20210728162655684](imgs/image-20210728162655684.png)

![image-20210728162049962](imgs/image-20210728162049962.png)

网络空间搜索引擎：Fofa和Shodan

![image-20210728162119531](imgs/image-20210728162119531.png)

IP反查域名

![image-20210728162303312](imgs/image-20210728162303312.png)

存活探测

![image-20210728162441132](imgs/image-20210728162441132.png)

漏洞检测

![image-20210728165612314](imgs/image-20210728165612314.png)

扫描结果保存在excel文件里

![image-20210728170303756](imgs/image-20210728170303756.png)

excel的内容如下

备案反查顶级域名

![image-20210728163926763](imgs/image-20210728163926763.png)

![image-20210728163940918](imgs/image-20210728163940918.png)

邮箱

![image-20210728164010063](imgs/image-20210728164010063.png)



Github敏感信息

![image-20210728164040649](imgs/image-20210728164040649.png)

爬虫

![image-20210728164146630](imgs/image-20210728164146630.png)

证书

![image-20210728164211552](imgs/image-20210728164211552.png)

子域名A记录和CDN

![image-20210728164316747](imgs/image-20210728164316747.png)

动态链接和后台地址

![image-20210728164555141](imgs/image-20210728164555141.png)

网络空间搜索引擎

![image-20210728164745820](imgs/image-20210728164745820.png)

ip反查域名

![image-20210728164811422](imgs/image-20210728164811422.png)

存活网站标题

![image-20210728164933353](imgs/image-20210728164933353.png)

指纹和漏洞

![image-20210728165004202](imgs/image-20210728165004202.png)

相关域名和C段

![image-20210728165052361](imgs/image-20210728165052361.png)

## 0x04 POC编写

POC的模板文件例子：`Plugins/Vul/Web/__template__.py`

只需要在run_detect方法里调用POC的利用方法即可。

## 0x05 使用方法 

| 语法                                                     | 功能                                          |
| :------------------------------------------------------- | :-------------------------------------------- |
| python3 ShuiZe.py -d domain.com                          | 收集单一的根域名资产                          |
| python3 ShuiZe.py --domainFile domain.txt                | 批量跑根域名列表                              |
| python3 ShuiZe.py -c 192.168.1.0,192.168.2.0,192.168.3.0 | 收集C段资产                                   |
| python3 ShuiZe.py -f url.txt                             | 对url里的网站漏洞检测                         |
| python3 ShuiZe.py --fofaTitle XXX大学                    | 从fofa里收集标题为XXX大学的资产，然后漏洞检测 |
| python3 ShuiZe.py -d domain.com --justInfoGather 1       | 仅信息收集，不检测漏洞                        |
| python3 ShuiZe.py -d domain.com --ksubdomain 0           | 不调用ksubdomain爆破子域名                    |

## 0x06 实现原理

* 备案反查顶级域名 -> 获取目标域名相关的其他根域名 -> 接口:http://icp.chinaz.com
* 判断是否是泛解析
  * 泛解析-> 不爆破子域名
  * 不是泛解析 -> 调用ksubdomain爆破子域名(脚本里我用的是linux版本的ksubdomain，文件地址:./Plugins/infoGather/subdomain/ksubdomain/ksubdomain_linux，如果是其他系统请自行替换)
* 调用theHarvester -> 获取子域名和邮箱列表
* 第三方数据接口 -> 获取子域名
  * virustotal -> https://www.virustotal.com -> 需要api
  * ce.baidu.com -> http://ce.baidu.com
  * url.fht.im -> https://url.fht.im/
  * qianxun -> https://www.dnsscan.cn/
  * sublist3r -> https://api.sublist3r.com
  * crt.sh -> https://crt.sh
  * certspotter -> https://api.certspotter.com
  * bufferover -> http://dns.bufferover.run	
  * threatcrowd -> https://threatcrowd.org
  * hackertarget -> https://api.hackertarget.com
  * chaziyu -> https://chaziyu.com/hbu.cn/
  * rapiddns -> https://rapiddns.io
  * sitedossier -> http://www.sitedossier.com
  * ximcx -> http://sbd.ximcx.cn		
* github -> 从github获取子域名，并把查询结果保存到txt-获取敏感信息
  * 敏感信息关键字匹配，可在iniFile/config.ini自定义关键字内容，内置如下关键字('jdbc:', 'password', 'username', 'database', 'smtp', 'vpn', 'pwd', 'passwd', 'connect')
* 百度和必应爬虫 -> 获取目标后台等地址('inurl:admin', 'inurl:login', 'inurl:system', 'inurl:register', 'inurl:upload', '后台', '系统', '登录')
* 证书 -> 获取目标关联域名
* 子域名友链 -> 获取未爆破出的子域名，未被收录的深层域名

![image-20210728132752381](imgs/image-20210728132752381.png)

整理上面所有的子域名

* 对所有子域名判断是否是CDN并解析出A记录

* 统计每个c段出现IP的个数

* 调用网络空间搜索引擎
  * fofa -> 需要API
  * shodan -> 需要API

* 前面获得的ip反查域名得到相关资产的子域名，整理出所有的子域名和IP


![image-20210728133047590](imgs/image-20210728133047590.png)

* 整理所有资产探测漏洞

  * Web -> 存活探测 

    * 获取标题 
      * 自动跑后台路径(['admin', 'login', 'system', 'manager', 'admin.jsp', 'login.jsp', 'admin.php', 'login.php','admin.aspx', 'login.aspx', 'admin.asp', 'login.asp'])
      * 如果URL是IP则查询IP的归属地
    * 漏洞检测 -> Plugins/Vul/Web

    ![image-20210728134051049](imgs/image-20210728134051049.png)

    ![image-20210728134115608](imgs/image-20210728134115608.png)

    ![image-20210728134131076](imgs/image-20210728134131076.png)

  * 非Web服务 --> 未授权和弱口令

  ![image-20210728134212279](imgs/image-20210728134212279.png)


其他功能

![image-20210728134304533](imgs/image-20210728134304533.png)

结果展示：

![image-20210728132105833](imgs/image-20210728132105833.png)

完整流程图:

![](imgs/xmind.png)


## 0x07 新增功能

2021.7.31 增加了Censys接口，需要在iniFile/config.ini的[censys api]中填入API。 功能是获取域名的所有解析IP记录，一是为了Host碰撞，二是更加准确的得到C段IP

需要censys的api，免费的账户一个月只有250次查询，所以后期需要注意，用完了要更新api

2021.7.31 增加了Host碰撞访问内网系统漏洞，感谢小洲提交的建议

![](imgs/hostCollide.png)

2021.8.1 修复了CDN判断的bug，感谢 leveryd 师傅提交的bug。

issues地址：https://github.com/0x727/ShuiZe_0x727/issues/3 

2021.8.3 修复了chinazApi接口请求超时太长的bug，设置默认时间10秒，感谢 k0njac 师傅提交的bug。

issues地址：https://github.com/0x727/ShuiZe_0x727/issues/11 

2021.8.13 增加了获取Github敏感信息地址的作者邮箱，帮助判断是否是目标员工的项目

2021.8.17 更新了ksubdomain版本，自动选择网卡，不需要重新手动输入网卡

ksubdomain项目地址：https://github.com/knownsec/ksubdomain

![](./imgs/github_auther.png)

2021.9.1 增加了从fofa中爬去socks代理功能，后续可以手动配合proxychains进行漏洞探测，防止因为被封IP导致漏报。

感谢团队的1amfine2333师傅提供的思路。

![](./imgs/socksProxy.png)

2021.9.2 增加了Confluence指纹识别，漏洞利用地址：https://github.com/h3v0x/CVE-2021-26084_Confluence

2021.9.4 增加了某查接口，对目标的整个架构分析，涵盖【对外投资、控股公司、分支机构、联系方式、邮箱】等信息。

感谢pykiller师傅提交的建议，同时参考了吐司师傅gubeiya的脚本

issues地址：https://github.com/0x727/ShuiZe_0x727/issues/25

![](./imgs/aiqicha.png)


2021.9.26 增加了夸克的api接口,-d -c --fofaTitle中都会调用

限定了每次最大查询数量1000条，不然一个月5w条数据也用不了多少次

在config.ini配置文件的quake_nums值

issues地址：https://github.com/0x727/ShuiZe_0x727/issues/33

![](./imgs/quakeApi.png)

![](./imgs/quakeApi2.png)


2021.11.30 增加了奇安信hunter的api接口,-d -c --fofaTitle中都会调用

限定了每次最大查询数量200条，不然一天的几千条数据也用不了多少次

在config.ini配置文件的qianxin_nums值

issues地址：https://github.com/0x727/ShuiZe_0x727/issues/48

![](./imgs/qianxinApi2.png)

![](./imgs/qianxinApi.png)

2022.1.17 修复了certspotter接口获取子域名过滤不严谨的问题

感谢union-cmd师傅提交的建议

issues地址：https://github.com/0x727/ShuiZe_0x727/issues/57



## 0x08 反馈

ShuiZe（水泽） 是一个免费且开源的项目，我们欢迎任何人为其开发和进步贡献力量。

* 在使用过程中出现任何问题，可以通过 issues 来反馈。
* Bug 的修复可以直接提交 Pull Request 到 dev 分支。
* 如果是增加新的功能特性，请先创建一个 issue 并做简单描述以及大致的实现方法，提议被采纳后，就可以创建一个实现新特性的 Pull Request。
* 欢迎对说明文档做出改善，帮助更多的人使用 ShuiZe。
* 贡献代码请提交 PR 至 dev 分支，master 分支仅用于发布稳定可用版本。

*提醒：和项目相关的问题最好在 issues 中反馈，这样方便其他有类似问题的人可以快速查找解决方法，并且也避免了我们重复回答一些问题。*

## Stargazers over time

[![Stargazers over time](https://starchart.cc/0x727/ShuiZe_0x727.svg)](https://starchart.cc/0x727/ShuiZe_0x727)

<img align='right' src="https://profile-counter.glitch.me/ShuiZe_0x727/count.svg" width="200">