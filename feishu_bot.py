import logging
import os
from concurrent.futures.thread import ThreadPoolExecutor
from flask import Flask, request, jsonify
import requests
import hashlib
from Crypto.Util.Padding import *
from Crypto.Cipher import AES


app = Flask(__name__)
SAVE_PATH = 'D:/sovits4.0'
LOG_FILE = 'feishu_bot.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
ENCRYPT_KEY = 'quzDNFngyjTf4IYG0IMxjf4fkzNRbllM'
APP_SECRET = 'a15pwxZuonht3KMfWIWmWhtpBfsxThrz'
VERIFICATION_TOKEN = 'I04jPOZlKLMFwuHRkoitTb6wLODybyQQ'

# 日志配置
if not os.path.exists(os.path.dirname(os.path.abspath(LOG_FILE))):
    os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)))

formatter = logging.Formatter(LOG_FORMAT)
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(formatter)
logger = logging.getLogger('FeishuBot')
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def verify_request(req):
    signature = req.headers.get('X-Signature')
    if not signature:
        return False
    return signature == hashlib.sha1((VERIFICATION_TOKEN + req.data.decode('utf-8')).encode('utf-8')).hexdigest()


def parse_event_data(data):
    encrypt = data['encrypt']
    cipher = AES.new(ENCRYPT_KEY, AES.MODE_CBC, ENCRYPT_KEY[:16])
    decrypted = unpad(cipher.decrypt(bytes.fromhex(encrypt)), 16).decode('utf-8')
    return eval(decrypted)['event']


def download_file(media_id, message_type):
    access_token = get_access_token()  # 获取飞书机器人的访问令牌
    file_url = f'https://open.feishu.cn/open-apis/media/v4/download/{media_id}?access_token={access_token}'
    response = requests.get(file_url)

    if response.status_code != 200:
        logger.error(f'{message_type} message download failed: {response.text}')
        return

    file_path = os.path.join(SAVE_PATH, f'{message_type}_{media_id}')
    with open(file_path, 'wb') as f:
        f.write(response.content)

    logger.info(f'{message_type} message downloaded successfully: {file_path}')


@app.route('/', methods=['POST'])
def receive_message():
    try:
        if not verify_request(request):
            logger.warning('Invalid request.')
            return '', 400

        event = parse_event_data(request.json)
        if event.get('type') == 'message':
            message_type = event.get('message').get('type')
            if message_type == 'image' or message_type == 'video':
                media_id = event.get('message').get('media_id')
                with ThreadPoolExecutor(max_workers=1) as executor:
                    executor.submit(download_file, media_id, message_type)

        return '', 200

    except Exception as e:
        logger.error(f'Error occur: {e}', exc_info=True)

    return '', 200


def get_access_token():
    url = 'https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal/'
    headers = {'Content-Type': 'application/json'}
    data = {'app_id': 'cli_a4e6d018bdfa1013', 'app_secret': 'a15pwxZuonht3KMfWIWmWhtpBfsxThrz'}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json().get('tenant_access_token')
    else:
        logger.error(f'Get access token failed: {response.text}')
        return ''


if __name__ == '__main__':
    if not os.path.exists(SAVE_PATH):
        os.makedirs(SAVE_PATH)

    app.run(debug=False)
