# seeyonExp
致远命令执行漏洞
### 1、概念

致远的通过javafx编写的GUI利用工具，主要包括下列的命令执行漏洞，JNDI相关的利用需要ChangeLocale_Rce、SursenServlet_Rce、log4j2，JNDI利用

![image-20230205213148579](README.assets/image-20230205213148579.png)

可以设置HTTP代理

![image-20230205213651891](README.assets/image-20230205213651891.png)

均可利用成功，由于环境机器坏了，所以暂时无法截图

### 2、使用方法

1、选择漏洞

2、输入地址

3、点击检查漏洞即可（需外联漏洞，主要通过dnslog.cn验证是否存在漏洞）

4、根据提示信息利用即可

