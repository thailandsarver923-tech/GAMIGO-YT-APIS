import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, base64, datetime, re, socket, threading, ssl, pytz, aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * 
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2, sQ_pb2, Team_msg_pb2
from cfonts import render, say
from aiohttp import web
import asyncio

# EMOTES BY PARAHEX X CODEX

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# Global Variables
#------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
current_key = None
current_iv = None
current_region = None
current_team_code = None
team_spam_running = False
#------------------------------------------#

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB50"}

# ---- Random Colors ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.114.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization'] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto

async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto

async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length'); headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'

async def SEndMsG(H, message, Uid, chat_id, key, iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message, chat_id, key, iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message, 1, chat_id, chat_id, key, iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message, 2, Uid, Uid, key, iv)
    return msg_packet

async def SEndPacKeT(OnLinE, ChaT, TypE, PacKeT):
    if TypE == 'ChaT' and ChaT: 
        whisper_writer.write(PacKeT) 
        await whisper_writer.drain()
    elif TypE == 'OnLine': 
        online_writer.write(PacKeT) 
        await online_writer.drain()
    else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)'

async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer, spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, XX, uid, Spy, data2, Chat_Leave
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break

                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        packet = json.loads(packet)
                        OwNer_UiD, CHaT_CoDe, SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3, OwNer_UiD, CHaT_CoDe, key, iv)
                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', JoinCHaT)

                        message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot API ! \n\n{get_random_color()}- API is running on port 8080\n\n[00FF00]Dev : @{xMsGFixinG("Spideerio")}'
                        P = await SEndMsG(0, message, OwNer_UiD, OwNer_UiD, key, iv)
                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                    except Exception as e:
                        print(f"Error processing squad data: {e}")
                        pass

            online_writer.close()
            await online_writer.wait_closed()
            online_writer = None

        except Exception as e:
            print(f"- ErroR With {ip}:{port} - {e}")
            online_writer = None
        await asyncio.sleep(reconnect_delay)

async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region, reconnect_delay=0.5):
    print(region, 'TCP CHAT')

    global spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, online_writer, chat_id, XX, uid, Spy, data2, Chat_Leave, current_team_code
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id, clan_compiled_data, key, iv)
                if whisper_writer:
                    whisper_writer.write(pK)
                    await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break

                if data.hex().startswith("120000"):
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()

                        print(f"Received message: {inPuTMsG} from UID: {uid} in chat type: {XX}")

                        # Handle /tc command to join team
                        if inPuTMsG.startswith("/tc"):
                            try:
                                # Extract team code after /tc
                                parts = inPuTMsG.split()
                                team_code = None
                                for part in parts:
                                    if part.startswith("tc="):
                                        team_code = part.split("=")[1].strip()
                                        break
                                    elif part != "/tc" and len(part) > 3:
                                        team_code = part
                                        break
                                
                                if team_code:
                                    current_team_code = team_code
                                    
                                    message = f"[B][C]{get_random_color()}\n\nJoining Team: {team_code}\n\n"
                                    P = await SEndMsG(XX, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    
                                    # Join the team
                                    join_packet = await GenJoinSquadsPacket(team_code, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
                                    
                                    await asyncio.sleep(0.1)
                                    
                                    message = f"[B][C]{get_random_color()}\n\nSuccessfully joined team: {team_code}\n\n"
                                    P = await SEndMsG(XX, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                else:
                                    message = f"[B][C]{get_random_color()}\n\nPlease provide team code: /tc TEAM_CODE\n\n"
                                    P = await SEndMsG(XX, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                            except Exception as e:
                                print(f"Error processing /tc command: {e}")
                                message = f"[B][C]{get_random_color()}\n\nError joining team! Check team code.\n\n"
                                P = await SEndMsG(XX, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                        # Handle /5 command in both friend chat and team chat
                        if inPuTMsG.startswith(("/5")):
                            try:
                                message = f"[B][C]{get_random_color()}\n\nAccepT My Invitation FasT\n\n"
                                P = await SEndMsG(XX, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                # Squad operations
                                PAc = await OpEnSq(key, iv, region)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
                                C = await cHSq(5, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
                                V = await SEnd_InV(5, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
                                E = await ExiT(None, key, iv)
                                await asyncio.sleep(3)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)

                            except Exception as e:
                                print(f"Error processing /5 command: {e}")

                        # Handle other commands
                        if inPuTMsG.startswith('/x/'):
                            CodE = inPuTMsG.split('/x/')[1]
                            try:
                                EM = await GenJoinSquadsPacket(CodE, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', EM)
                            except Exception as e:
                                print(f"Error processing join code: {e}")

                        if inPuTMsG.startswith('leave'):
                            leave = await ExiT(uid, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave)

                        if inPuTMsG.strip().startswith('/s'):
                            EM = await FS(key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', EM)

                    except Exception as e:
                        print(f"Error processing message: {e}")

            whisper_writer.close()
            await whisper_writer.wait_closed()
            whisper_writer = None

        except Exception as e:
            print(f"ErroR {ip}:{port} - {e}")
            whisper_writer = None
        await asyncio.sleep(reconnect_delay)

# Team Spam Function
async def team_spam_loop(team_code, key, iv):
    global team_spam_running, online_writer
    
    team_spam_running = True
    print(f"🚀 Starting team spam for team: {team_code}")
    
    for i in range(100):
        if not team_spam_running:
            break
            
        try:
            # Join team
            print(f"🔄 [{i+1}/100] Joining team...")
            join_packet = await GenJoinSquadsPacket(team_code, key, iv)
            await SEndPacKeT(None, None, 'OnLine', join_packet)
            await asyncio.sleep(0.1)  # Wait for join
            
            # Leave team
            print(f"🚪 [{i+1}/100] Leaving team...")
            leave_packet = await ExiT(None, key, iv)
            await SEndPacKeT(None, None, 'OnLine', leave_packet)
            await asyncio.sleep(0.1)  # Wait for leave
            
        except Exception as e:
            print(f"❌ Error in team spam iteration {i+1}: {e}")
            await asyncio.sleep(0.1)
    
    team_spam_running = False
    print("✅ Team spam completed!")

# API Routes
async def handle_join(request):
    global online_writer, current_key, current_iv, current_region, current_team_code
    
    try:
        # Get parameters from query string
        uid1 = request.query.get('uid1')
        uid2 = request.query.get('uid2')
        uid3 = request.query.get('uid3')
        uid4 = request.query.get('uid4')
        emote_id = request.query.get('emote_id', '909000098')
        team_code = request.query.get('tc')
        
        # Validate required parameters
        if not uid1:
            return web.json_response({
                "status": "error",
                "message": "uid1 is required"
            }, status=400)
        
        # Prepare UIDs list
        uids = [uid1]
        if uid2: uids.append(uid2)
        if uid3: uids.append(uid3)
        if uid4: uids.append(uid4)
        
        # Convert UIDs to integers
        uids_int = []
        for uid in uids:
            try:
                uids_int.append(int(uid))
            except ValueError:
                return web.json_response({
                    "status": "error",
                    "message": f"Invalid UID format: {uid}"
                }, status=400)
        
        # Convert emote_id to integer
        try:
            emote_id_int = int(emote_id)
        except ValueError:
            return web.json_response({
                "status": "error",
                "message": f"Invalid emote_id format: {emote_id}"
            }, status=400)
        
        # Check if bot is connected
        if not online_writer:
            return web.json_response({
                "status": "error",
                "message": "Bot is not connected to Free Fire servers"
            }, status=503)
        
        # If team code is provided, join the team first
        if team_code:
            try:
                print(f"Joining team: {team_code}")
                join_packet = await GenJoinSquadsPacket(team_code, current_key, current_iv)
                await SEndPacKeT(None, None, 'OnLine', join_packet)
                await asyncio.sleep(3)  # Wait for team join to complete
                current_team_code = team_code
            except Exception as e:
                print(f"Error joining team: {e}")
                return web.json_response({
                    "status": "error",
                    "message": f"Failed to join team: {str(e)}"
                }, status=500)
        
        # Send emotes to all UIDs
        success_count = 0
        for uid in uids_int:
            try:
                emote_packet = await Emote_k(uid, emote_id_int, current_key, current_iv, current_region)
                await SEndPacKeT(None, None, 'OnLine', emote_packet)
                success_count += 1
                await asyncio.sleep(0.2)  # Small delay between emotes
            except Exception as e:
                print(f"Error sending emote to UID {uid}: {e}")
        
        # Prepare response
        response_data = {
            "emote_id": emote_id,
            "message": f"Emote performed successfully on {success_count} players!",
            "status": "success",
            "team_code": team_code if team_code else current_team_code if current_team_code else "Not provided",
            "uids": uids
        }
        
        return web.json_response(response_data)
        
    except Exception as e:
        return web.json_response({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }, status=500)

async def handle_join_team(request):
    global online_writer, current_key, current_iv, current_team_code
    
    try:
        team_code = request.query.get('tc')
        
        if not team_code:
            return web.json_response({
                "status": "error",
                "message": "Team code (tc) is required"
            }, status=400)
        
        # Check if bot is connected
        if not online_writer:
            return web.json_response({
                "status": "error",
                "message": "Bot is not connected to Free Fire servers"
            }, status=503)
        
        # Join the team
        try:
            join_packet = await GenJoinSquadsPacket(team_code, current_key, current_iv)
            await SEndPacKeT(None, None, 'OnLine', join_packet)
            await asyncio.sleep(0.1)  # Wait for team join to complete
            current_team_code = team_code
            
            return web.json_response({
                "status": "success",
                "message": f"Successfully joined team: {team_code}",
                "team_code": team_code
            })
            
        except Exception as e:
            return web.json_response({
                "status": "error",
                "message": f"Failed to join team: {str(e)}"
            }, status=500)
            
    except Exception as e:
        return web.json_response({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }, status=500)

async def handle_team_spam(request):
    global online_writer, current_key, current_iv, team_spam_running
    
    try:
        team_code = request.query.get('tc')
        
        if not team_code:
            return web.json_response({
                "status": "error",
                "message": "Team code (tc) is required"
            }, status=400)
        
        # Check if bot is connected
        if not online_writer:
            return web.json_response({
                "status": "error",
                "message": "Bot is not connected to Free Fire servers"
            }, status=503)
        
        # Check if spam is already running
        if team_spam_running:
            return web.json_response({
                "status": "error",
                "message": "Team spam is already running"
            }, status=400)
        
        # Start team spam in background
        asyncio.create_task(team_spam_loop(team_code, current_key, current_iv))
        
        return web.json_response({
            "status": "success",
            "message": f"Team spam started for team: {team_code}",
            "iterations": 100,
            "team_code": team_code
        })
            
    except Exception as e:
        return web.json_response({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }, status=500)

async def handle_stop_spam(request):
    global team_spam_running
    
    if team_spam_running:
        team_spam_running = False
        return web.json_response({
            "status": "success",
            "message": "Team spam stopped"
        })
    else:
        return web.json_response({
            "status": "error",
            "message": "No team spam running"
        })

async def handle_status(request):
    global online_writer, whisper_writer, current_team_code, team_spam_running
    return web.json_response({
        "status": "success",
        "bot_online": online_writer is not None,
        "bot_chat": whisper_writer is not None,
        "current_team": current_team_code if current_team_code else "Not in team",
        "team_spam_running": team_spam_running,
        "message": "Free Fire Emote Bot API is running"
    })

async def handle_health(request):
    return web.json_response({
        "status": "success",
        "message": "API is healthy",
        "timestamp": datetime.now().isoformat()
    })

async def start_api_server():
    """Start the API server"""
    app = web.Application()
    
    # Add routes
    app.router.add_get('/join', handle_join)
    app.router.add_get('/join-team', handle_join_team)
    app.router.add_get('/team-spam', handle_team_spam)
    app.router.add_get('/stop-spam', handle_stop_spam)
    app.router.add_get('/status', handle_status)
    app.router.add_get('/health', handle_health)
    app.router.add_get('/', handle_status)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    await site.start()
    
    print(f"🚀 API Server started on http://0.0.0.0:8080")
    print(f"📊 Endpoints:")
    print(f"   GET /join?uid1=X&uid2=Y&emote_id=Z&tc=TEAM_CODE")
    print(f"   GET /join-team?tc=TEAM_CODE")
    print(f"   GET /team-spam?tc=TEAM_CODE")
    print(f"   GET /stop-spam")
    print(f"   GET /status - Check bot status")
    print(f"   GET /health - Health check")
    print(f"💬 Chat Commands:")
    print(f"   /tc TEAM_CODE - Join team")
    print(f"   /5 - Send invitation")
    print(f"   /x/TEAM_CODE - Join team")
    print(f"   leave - Leave current team")
    
    return runner

async def MaiiiinE():
    global current_key, current_iv, current_region
    
    Uid, Pw = '4247903706', 'NR-CODEX-TP7WIUQ6O-NILAY'

    open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
    if not open_id or not access_token:
        print("ErroR - InvaLid AccounT")
        return None

    PyL = await EncRypTMajoRLoGin(open_id, access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE:
        print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ")
        return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region
    current_region = region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    current_key = key
    current_iv = iv
    timestamp = MajoRLoGinauTh.timestamp

    LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
    if not LoGinDaTa:
        print("ErroR - GeTinG PorTs From LoGin DaTa !")
        return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP, OnLineporT = OnLinePorTs.split(":")
    ChaTiP, ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    print(f"Account Name: {acc_name}")
    print(f"Token: {ToKen}")

    AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
    ready_event = asyncio.Event()

    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region))

    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP, OnLineporT, key, iv, AutHToKen))
    
    os.system('clear')
    print(render('REDZED API', colors=['white', 'green'], align='center'))
    print('')
    print(f" - ReGioN => {region}")
    print(f" - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")
    print(f" - API Server > Running on port 8080 !")
    print(f" - Subscribe > Spideerio | Gaming ! (:")
    
    await asyncio.gather(task1, task2)

async def StarTinG():
    # Start API server
    api_runner = await start_api_server()
    
    # Start Free Fire bot with reconnection logic
    while True:
        try:
            await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError:
            print("Token ExpiRed ! , ResTartinG")
        except Exception as e:
            print(f"ErroR TcP - {e} => ResTarTinG ...")
        await asyncio.sleep(5)

import sys

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"[🚀] Starting {__name__.upper()} on port {port} ...")
    try:
        asyncio.run(startup())
    except Exception as e:
        print(f"[⚠️] Startup warning: {e} — continuing without full initialization")
    app.run(host='0.0.0.0', port=port, debug=False)
