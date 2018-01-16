## A net sniffer2.
- 实现一个功能比较简单的、具有图形界面的Sniffer，主线程响应用户界面操作，工作线程完成抓包等工作；
- 够解析出IP层和传输层的协议头，能够过滤TCP、UDP等数据包；
- 能够输出文本方式传送的数据包的内容；
- 能够进行简单的流量统计。
- 能够将捕获到的数据包写入文件。

- 开发工具：Intellij IDEA
- 附加库  ：winpcap，jNetPcap

![软件启动主界面](https://github.com/gyhua96/Sniffer/raw/master/screen-shots/main.png)  

软件启动主界面  
  
  
![选择网络设备界面](https://github.com/gyhua96/Sniffer/raw/master/screen-shots/interface.png)  
  选择网络设备界面  
  
![选择筛选协议界面](https://github.com/gyhua96/Sniffer/raw/master/screen-shots/flitter.png)  
选择筛选协议界面  
  
![嗅探器开始工作界面](https://github.com/gyhua96/Sniffer/raw/master/screen-shots/working.png)  
嗅探器开始工作界面  

![将捕获到的数据包写入文件功能界面,用保存时间命名文件](https://github.com/cheng-github/Sniffer/blob/master/screen-shots/save1.PNG)
(https://github.com/cheng-github/Sniffer/blob/master/screen-shots/save2.PNG)
