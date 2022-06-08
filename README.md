# vt-debugger
vt框架使用的airhv,增加了自建调试体系部分,稍微修改下可以调试大部分游戏,给学习vt的同学参考
vt调试器:
1. ept hook.
2. 无痕int3.
3. 自建调试体系隐藏debugport.
4. 支持pdb符号自动下载，省去寻找特征码步骤,轻松兼容不同系统版本.
5. 5.zip文件是编译好的成品，后面会持续更新
6. 支持平台 win10 x64 intel architecture cpu.
7. 如果你在虚拟机里测试:虚拟机的配置:[内存>=4GB, cpu核心数>=2]

the soruce code is based in hyperhide, with less modify it can debug a lot games.
vt debugger:
1. ept hook.
2. invisible int3 breakpoint.
3. self constrcution of debug system hide debugport.
4. 4. download pdb automally, compatible with different system.
5. 5.zip file is compiled, it will update constantly
6. support platform win10 x64 intel architecture cpu.
7. if you test on virtual machine [virtual machine config:memory >=4GB, cpu core>=2]

![vtDebugger](https://user-images.githubusercontent.com/22963370/172332062-c2093279-8377-41ae-ace0-bc52a389b974.png)
