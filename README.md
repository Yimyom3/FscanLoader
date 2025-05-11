# FscanLoader

一个用于绕过杀软加载fscan的加载器
## 实现

+ 使用CGO技术将fscan项目编译成dll，并链接反射式加载静态库
+ loader动态获取所需API，寻找dll的反射式加载入口，完成fscan的加载

## 编译
1. 确保已安装MSVC、GCC(MinGW64)、Go环境
2. 拉取fscan项目
   ```bash
   git clone https://github.com/shadow1ng/fscan.git
   ```
3. 将fscan项目的main.go替换为以下内容
   ```Go
   package main
    
    /*
    #cgo LDFLAGS: -L${SRCDIR}/lib -lreflective
    void DllInit();
    */
    import "C"
    import (
    	"fmt"
    	"os"
    
    	"github.com/shadow1ng/fscan/Common"
    	"github.com/shadow1ng/fscan/Core"
    )
    
    //export DllRegisterServer
    func DllRegisterServer() {}
    
    func init() {
    	C.DllInit() //注册接受退出信号的回调函数
    	Common.InitLogger()
    	var Info Common.HostInfo
    	Common.Flag(&Info)
    	if err := Common.Parse(&Info); err != nil {
    		os.Exit(1)
    	}
    	// 初始化输出系统，如果失败则直接退出
    	if err := Common.InitOutput(); err != nil {
    		Common.LogError(fmt.Sprintf("初始化输出系统失败: %v", err))
    		os.Exit(1) // 关键修改：初始化失败时直接退出
    	}
    	defer Common.CloseOutput()
    	Core.Scan(Info)
    }
    
    func main() {}
   ```
  4. 在fscan项目下的/Common/Flag.go的Flag函数(58行)中添加以下代码
     ```Go
     //加载器参数兼容
     flag.Bool("fl", false, "从文件中加载fscan(默认model.bin)")
     flag.Bool("ul", false, "从URL中加载fscan")
     flag.Bool("xk", false, "设置加载fscan的xor密钥")
     ```
 5. 将本项目的lib目录拷贝到fscan项目下，执行命令生成libreflective.a文件
    ```shell
    gcc -O0 -c -o libreflective.a reflective.c
    ```
 6. 在fscan项目下执行命令生成fscan.dll文件，将fscan.dll的第3、4、5、6字节内容都修改为 **0x90**
    ```shell
    go build -buildmode=c-shared -ldflags="-w -s" -o fscan.dll 
    ```
    ![image](https://github.com/user-attachments/assets/3aaddeca-cc6a-4d6a-aeaa-b97cf06111f6)

 7. 使用Visual Studio打开FscanLoader项目，选择x64架构，一键编译即可

## 使用方法

+ 使用 **-fl**参数从文件中加载，如果不提供参数值，则默认从当前目录下的 **model.bin**中加载
  ![image](https://github.com/user-attachments/assets/c0b6b118-5091-45a5-95b1-224ed6ed87bc)

+ 使用 **-ul**参数从 **URL** 加载
  ![url](https://github.com/user-attachments/assets/392813b9-1b4a-4b1a-bab6-844faf9e5af9)


+ 支持对加载内容进行xor解密，使用 **-xk** 参数指定xor密钥
  ![image](https://github.com/user-attachments/assets/8d2cc6e5-4565-430a-bdbb-25c36163faec)
  ![image](https://github.com/user-attachments/assets/94063a1d-d686-404f-9f55-d2351dc53629)


> 其余参数和fscan一致

## 效果
+ 微步云沙箱
  ![image](https://github.com/user-attachments/assets/0aa335c5-162d-45cf-9a04-24ab368f68df)

+ vt
   ![image](https://github.com/user-attachments/assets/0658a07b-3c7e-495f-9f95-9e09e7f51e02)

+ 360核晶
  ![360](https://github.com/user-attachments/assets/1cc5a1d7-6ab8-4a16-a3ef-afe026fd21b3)

+ 火绒
  ![image](https://github.com/user-attachments/assets/a14eacc5-96b1-44cd-87ed-ded8eb67d73e)

+ Windows Defender
  ![Snipaste_2025-05-11_20-09-50](https://github.com/user-attachments/assets/aaf919e0-a613-4fea-81a4-6e26499f5311)


## 注意事项

+ 使用gcc编译静态库时一定要加 **-O0** 参数关闭编译器优化
+ go build 命令务必添加 **-ldflags="-w -s**"参数来缩小dll的体积
+ 仅在x86_64环境上测试，如需其他环境，请自行编译和验证

## 参考

[https://mp.weixin.qq.com/s/b0mphQG-nny0X087JsjsKQ](https://mp.weixin.qq.com/s/Yuk7Ev_JP8JAf_8uvIhdVw)

https://github.com/shadow1ng/fscan

## 免责声明

(1) 本项目仅用于网络安全技术的学习研究。旨在提高安全开发能力，研发新的攻防技术。

(2) 若执意要将本项目用于渗透测试等安全业务，需先确保已获得足够的法律授权，在符合网络安全法的条件下进行。

(3) 本项目由个人独立开发，暂未做全面的软件测试，请使用者在虚拟环境中测试本项目功能。

(4) 本项目完全开源，请勿将本项目用于任何商业用途。

(5) 若使用者在使用本项目的过程中存在任何违法行为或造成任何不良影响，需使用者自行承担责任，与项目作者无关。
