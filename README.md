# feishu-png
from larksuiteoapi import Config, DefaultLogger, LEVEL_INFO, DOMAIN_FEISHU_CHINA, DOMAIN_FEISHU_GLOBAL
from larksuiteoapi import OpenApiClient, RetryType
from larksuiteoapi.model import Image, Video
import os

# 配置日志
config = Config.new_config_with_memory_store(
#"your app id",
   
#"your app secret",
  
#"your verification token",
   
#"your encrypt key",

)
config.logger.setLevel(LEVEL_INFO)
logger = DefaultLogger(config.logger)

# 设置机器人ID和下载路径
bot_id = "cli_a4e6d018bdfa1013"
download_path = "D:\feishu-beifen"

# 初始化客户端
client = OpenApiClient(config=config, logger=logger)

# 处理图片消息
def process_image(event):
    image = client.files.download_media(media_id=event.message.image_key, image_type=Image.TYPE_ORIGIN)
    file_path = os.path.join(download_path, event.message.image_key + ".jpg")
    with open(file_path, "wb") as f:
        f.write(image["data"])
    print("Image saved to {0}".format(file_path))

# 处理视频消息
def process_video(event):
    video = client.files.download_media(media_id=event.message.video_key, image_type=Video.TYPE_VIDEO)
    file_path = os.path.join(download_path, event.message.video_key + ".mp4")
    with open(file_path, "wb") as f:
        f.write(video["data"])
    print("Video saved to {0}".format(file_path))

# 监听机器人消息
def handle_bot_event(event):
    if event["type"] == "message" and (event["message"].get("image_key") or event["message"].get("video_key")):
        if event["message"].get("image_key"):
            process_image(event)
        elif event["message"].get("video_key"):
            process_video(event)

# 启动机器人
bot = client.bot.init_wss_bot(bot_id=bot_id, on_event=handle_bot_event, domain=DOMAIN_FEISHU_CHINA, auto_reconnect=True, retry_type=RetryType.Backoff)
bot.run()
