# 水泽-信息收集自动化工具

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

## 0x01 介绍

作者：Ske

团队：0x727，未来一段时间将陆续开源工具，地址：https://github.com/0x727

定位：协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点

语言：python3开发

功能：一条龙服务，只需要输入根域名即可全方位收集相关资产，并检测漏洞。也可以输入多个域名、C段IP等，具体案例见下文。

调用：脚本借用了ksubdomain爆破子域名和theHarvester收集邮箱，感谢ksubdomain和theHarvester作者

## 0x02 安装

为了避免踩坑,建议安装在如下环境中

* 当前用户对该目录有写权限，不然扫描结果无法生成。root权限即可
* Python环境必须是3.7以上，因为使用了异步。建议VPS环境是ubuntu20，默认是python3.8

* 在配置文件iniFile/config.ini里加入api（fofa、shodan、github、virustotal）

```
chmod 777 build.sh
./build.sh
```

![image-20210728153419131](imgs/image-20210728153419131.png)

`python3 ShuiZe.py -h`

![image-20210728154929084](imgs/image-20210728154929084.png)

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

