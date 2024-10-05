from pbf.utils import MetaData
from pbf.utils.Config import Config
from pbf.utils.Register import Command
from pbf.utils.CQCode import CQCode
from pbf.setup import logger
from pbf import config as defaultConfig
from pbf.controller.Data import Event
from pbf.controller.Client import Msg, Client
from pbf.statement import Statement

class FaceStatement(Statement):
    cqtype: str = "face"
    id: str = None

    def __init__(self, id: str):
        self.id = str(id)


class MyConfig(Config):
    originData = {
        "owner_id": 114514
    }
config = MyConfig(defaultConfig.plugins_config.get("GroupManagement", {}))


def adminPermission(event):
    if event.sender.get("role", "member") in ["admin", "owner"]:
        return True
    Msg([
        FaceStatement(1), " 403 Forbidden\n"
        "您需要的权限：管理员\n"
    ], event=event).send()
    return False

# 特别坑的两点（在PigBotFramework<=5.0.10中）：
# - 位于pbf.utils.Register包中的ownerPermission实际上指的是群主权限，而不是机器人主人权限
# - pbf.config没有为机器人主人的设置预留位置
# 综上所述，PBF作者就是个**（
def ownerPermission(event):
    if event.user_id == config.get("owner_id"):
        return True
    Msg([
        FaceStatement(1), " 403 Forbidden\n"
        "您需要的权限：机器人主人\n"
    ], event=event).send()
    return False


meta_data = MetaData(
    name="群聊管理",
    version="0.0.1",
    versionCode=1,
    description="群管理插件",
    author="XzyStudio",
    license="MIT",
    keywords=["pbf", "plugin", "groupmanagement"],
    readme="""
# GroupManagement
    """
)


class Api:
    @staticmethod
    def delete_msg(message_id: str):
        return Client().request("delete_msg", {"message_id": message_id})
    
    @staticmethod
    def get_msg(message_id: str):
        return Client().request("get_msg", {"message_id": message_id})
    
    @staticmethod
    def get_forward_msg(id: str):
        return Client().request("get_forward_msg", {"id": id})

    @staticmethod
    def send_like(user_id: int, times: int=1):
        return Client().request("send_like", {"user_id": user_id, "times": times})

    @staticmethod
    def set_group_kick(group_id: int, user_id: int, reject_add_request: bool = False):
        return Client().request("set_group_kick", {"group_id": group_id, "user_id": user_id, "reject_add_request": reject_add_request})

    @staticmethod
    def set_group_ban(group_id: int, user_id: int, duration: int = 30*60):
        return Client().request("set_group_ban",  {"group_id": group_id, "user_id": user_id, "duration": duration})

    @staticmethod
    def set_group_anonymous_ban(group_id: int, anonymous=None, flag: str="", duration: int = 30*60):
        return Client().request("set_group_anonymous_ban", {"group_id": group_id, "anonymous": anonymous, "flag": flag, "duration": duration})

    @staticmethod
    def set_group_whole_ban(group_id: int, enable: bool = True):
        return Client().request("set_group_whole_ban", {"group_id": group_id, "enable": enable})

    @staticmethod
    def set_group_admin(group_id: int, user_id: int, enable: bool = True):
        return Client().request("set_group_admin", {"group_id": group_id, "user_id": user_id, "enable": enable})

    @staticmethod
    def set_group_anonymous(group_id: int, enable: bool = True):
        return Client().request("set_group_anonymous", {"group_id": group_id, "enable": enable})

    @staticmethod
    def set_group_card(group_id: int, user_id: int, card: str=""):
        return Client().request("set_group_card", {"group_id": group_id, "user_id": user_id, "card": card})

    @staticmethod
    def set_group_name(group_id: int, group_name: str):
        return Client().request("set_group_name", {"group_id": group_id, "group_name": group_name})

    @staticmethod
    def set_group_leave(group_id: int, is_dismiss: bool = False):
        return Client().request("set_group_leave", {"group_id": group_id, "is_dismiss": is_dismiss})

    @staticmethod
    def set_group_special_title(group_id: int, user_id: int, special_title: str="", duration: int = -1):
        return Client().request("set_group_special_title", {"group_id": group_id, "user_id": user_id, "special_title": special_title, "duration": duration})

    @staticmethod
    def set_friend_add_request(flag: str, approve: bool = True, remark: str=""):
        return Client().request("set_friend_add_request", {"flag": flag, "approve": approve, "remark": remark})

    @staticmethod
    def set_group_add_request(flag: str, sub_type: str, approve: bool = True, reason: str=""):
        return Client().request("set_group_add_request", {"flag": flag, "sub_type": sub_type, "approve": approve, "reason": reason})

    @staticmethod
    def get_login_info():
        return Client().request("get_login_info", {})

    @staticmethod
    def get_stranger_info(user_id: int, no_cache: bool = False):
        return Client().request("get_stranger_info", {"user_id": user_id, "no_cache": no_cache})

    @staticmethod
    def get_friend_list():
        return Client().request("get_friend_list", {})

    @staticmethod
    def get_group_info(group_id: int, no_cache: bool = False):
        return Client().request("get_group_info", {"group_id": group_id, "no_cache": no_cache})

    @staticmethod
    def get_group_list():
        return Client().request("get_group_list", {})

    @staticmethod
    def get_group_member_info(group_id: int, user_id: int, no_cache: bool = False):
        return Client().request("get_group_member_info", {"group_id": group_id, "user_id": user_id, "no_cache": no_cache})

    @staticmethod
    def get_group_member_list(group_id: int):
        return Client().request("get_group_member_list", {"group_id": group_id})

    @staticmethod
    def get_group_honor_info(group_id: int, type: str):
        return Client().request("get_group_honor_info", {"group_id": group_id, "type": type})

    @staticmethod
    def get_cookies(domain: str):
        return Client().request("get_cookies", {"domain": domain})

    @staticmethod
    def get_csrf_token():
        return Client().request("get_csrf_token", {})

    @staticmethod
    def get_credentials(domain: str):
        return Client().request("get_credentials", {"domain": domain})

    @staticmethod
    def get_record(file: str, out_format: str="mp3"):
        return Client().request("get_record", {"file": file, "out_format": out_format})

    @staticmethod
    def get_image(file: str):
        return Client().request("get_image", {"file": file})

    @staticmethod
    def can_send_image():
        return Client().request("can_send_image", {})

    @staticmethod
    def can_send_record():
        return Client().request("can_send_record", {})

    @staticmethod
    def get_status():
        return Client().request("get_status", {})

    @staticmethod
    def get_version_info():
        return Client().request("get_version_info", {})

    @staticmethod
    def set_restart(delay: int = 0):
        return Client().request("set_restart", {"delay": delay})

    @staticmethod
    def clean_cache():
        return Client().request("clean_cache", {})

    @staticmethod
    def check_args(args: list, length: int, event: Event=None):
        operator: bool = True
        if isinstance(args, str):
            args = args.strip().split(" ")
        if len(args) < length+1:
            if event is not None:
                Msg([
                    FaceStatement(1), " 400 Bad Request\n"
                    f"缺少参数，目标个数：{length}\n"
                ], event=event).send()
            operator = False
        args[0] = operator
        # logger.debug(f"check_args: {args}")
        return args

    @staticmethod
    def check_result(res: dict, event: Event = None):
        if res.get("retcode", 0) not in [0, 1]:
            if event is not None:
                Msg([
                    FaceStatement(1), " 500 Internal Server Error\n"
                    f"操作失败：{res.get('retcode', 'UnknownError')}\n"
                ], event=event).send()
            logger.warning(f"操作失败：{res}")
            return False
        if event is not None:
            Msg([
                FaceStatement(3), " 200 OK\n"
            ], event=event).send()
        return True


def get_id(cqcode: str, key: str="qq") -> int:
    if "[CQ:" not in cqcode:
        return int(cqcode)
    return int(CQCode(cqcode).get(key)[0])


@Command(
    name="撤回",
    usage="撤回 <消息ID>",
    description="撤回一条消息",
    permission=adminPermission
)
def delete_msg(event: Event):
    status, message_id = Api.check_args(event.message, 2, event)
    if not status:
        return
    Api.check_result(Api.delete_msg(message_id), event)

@Command(
    name="点赞",
    usage="点赞 <用户ID> <次数>",
    description="给用户点赞",
    permission=ownerPermission
)
def send_like(event: Event):
    status, user_id, times = Api.check_args(event.message, 2, event)
    if not status:
        return
    user_id = get_id(user_id)
    Api.check_result(Api.send_like(user_id, times), event)

@Command(
    name="踢出",
    usage="踢出 <用户ID>",
    description="踢出群成员",
    permission=adminPermission
)
def set_group_kick(event: Event):
    status, user_id = Api.check_args(event.message, 1, event)
    if not status:
        return
    user_id = get_id(user_id)
    Api.check_result(Api.set_group_kick(event.group_id, user_id), event)

@Command(
    name="禁言",
    usage="禁言 <用户ID> <时长(0解封)>",
    description="禁言群成员",
    permission=adminPermission
)
def set_group_ban(event: Event):
    status, user_id, duration = Api.check_args(event.message, 2, event)
    if not status:
        return
    user_id = get_id(user_id)
    Api.check_result(Api.set_group_ban(int(event.group_id), user_id, duration), event)

@Command(
    name="匿名禁言",
    usage="匿名禁言 <匿名信息> <时长(0解封)>",
    description="匿名禁言群成员",
    permission=adminPermission
)
def set_group_anonymous_ban(event: Event):
    status, anonymous, duration = Api.check_args(event.message, 2, event)
    if not status:
        return
    Api.check_result(Api.set_group_anonymous_ban(event.group_id, anonymous, duration=duration), event)

@Command(
    name="全员禁言",
    usage="全员禁言 <开启/关闭>",
    description="全员禁言",
    permission=adminPermission
)
def set_group_whole_ban(event: Event):
    status, enable = Api.check_args(event.message, 1, event)
    if not status:
        return
    if enable == "开启":
        enable = True
    elif enable == "关闭":
        enable = False
    Api.check_result(Api.set_group_whole_ban(event.group_id, enable), event)

@Command(
    name="设置管理员",
    usage="设置管理员 <用户ID> <开启/关闭>",
    description="设置管理员",
    permission=adminPermission
)
def set_group_admin(event: Event):
    status, user_id, enable = Api.check_args(event.message, 2, event)
    if not status:
        return
    if enable == "开启":
        enable = True
    elif enable == "关闭":
        enable = False
    user_id = get_id(user_id)
    Api.check_result(Api.set_group_admin(event.group_id, user_id, enable), event)

@Command(
    name="匿名",
    usage="匿名 <开启/关闭>",
    description="匿名",
    permission=adminPermission
)
def set_group_anonymous(event: Event):
    status, enable = Api.check_args(event.message, 1, event)
    if not status:
        return
    if enable == "开启":
        enable = True
    elif enable == "关闭":
        enable = False
    Api.check_result(Api.set_group_anonymous(event.group_id, enable), event)

@Command(
    name="设置名片",
    usage="设置名片 <用户ID> <名片>",
    description="设置名片",
    permission=adminPermission
)
def set_group_card(event: Event):
    status, user_id, card = Api.check_args(event.message, 2, event)
    if not status:
        return
    user_id = get_id(user_id)
    Api.check_result(Api.set_group_card(event.group_id, user_id, card), event)

@Command(
    name="设置群名",
    usage="设置群名 <群名>",
    description="设置群名",
    permission=adminPermission
)
def set_group_name(event: Event):
    status, group_name = Api.check_args(event.message, 1, event)
    if not status:
        return
    Api.check_result(Api.set_group_name(event.group_id, group_name), event)

@Command(
    name="BOT退群",
    usage="BOT退群 确认",
    description="退群",
    permission=adminPermission
)
def set_group_leave(event: Event):
    status, sure = Api.check_args(event.message, 1, event)
    if not status:
        return
    if sure != "确认":
        return
    Api.check_result(Api.set_group_leave(event.group_id), event)

@Command(
    name="设置群头衔",
    usage="设置群头衔 <用户ID> <头衔> <时长(-1永久)>",
    description="设置群头衔",
    permission=adminPermission
)
def set_group_special_title(event: Event):
    status, user_id, special_title, duration = Api.check_args(event.message, 2, event)
    if not status:
        return
    user_id = get_id(user_id)
    Api.check_result(Api.set_group_special_title(event.group_id, user_id, special_title, duration), event)
