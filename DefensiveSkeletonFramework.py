import json
import time
import secrets
import threading
import hashlib
import ipaddress
import random
import logging

from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from queue import Queue, Empty


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("DefensiveOffense")


class AttackerSignalCollector:

    def __init__(self):
        self.malicious_agents = {
            "sqlmap","nmap","masscan","gobuster","dirbuster",
            "nuclei","zgrab","feroxbuster","wfuzz","nikto",
            "burp","zap","arachni","wpscan","joomscan",
            "metasploit","openvas","nessus","acunetix","netsparker"
        }

        self.attack_patterns = [
            "union select","1=1","script>alert","<svg onload",
            "etc/passwd","../","admin'--","or 1=1","exec sp_",
            "waitfor delay","; drop table","having 1=1",
            "benchmark(","sleep(","pg_sleep","xp_cmdshell",
            "reverse shell","eval(","base64_decode"
        ]

        self.bad_ips = {
            "45.79.123.45","167.99.200.88","185.220.101.12"
        }

    def assess_request(self, req: dict):

        ua = req.get("user_agent","").lower()
        ip = req.get("source_ip","0.0.0.0")
        uri = req.get("uri","/")
        method = req.get("method","GET")
        body = req.get("body","")
        params = req.get("query_params",{})

        signals = {

            "suspicious_ua": any(a in ua for a in self.malicious_agents),

            "tor_exit": self.is_tor_exit(ip),

            "high_rate": req.get("requests_last_minute",0) > 50,

            "sensitive_probe":
                any(x in uri for x in [
                    "/.env","/.git/config","/wp-config.php",
                    "/adminer.php","/debug.log"
                ]),

            "payload_attack":
                any(p in body.lower() or
                    any(p in str(v).lower() for v in params.values())
                    for p in self.attack_patterns),

            "known_bad_ip": ip in self.bad_ips
        }

        pressure = self.calculate_pressure(signals)

        artifact = hashlib.sha256(
            f"{json.dumps(req,sort_keys=True)}{datetime.now(timezone.utc)}".encode()
        ).hexdigest()[:32]

        return {
            "signals":signals,
            "pressure_score":pressure,
            "artifact":artifact
        }

    def is_tor_exit(self, ip):

        try:
            addr = ipaddress.ip_address(ip)
            return (
                addr.is_private
                or str(addr).startswith("185.220.")
                or str(addr).startswith("89.234.")
            )
        except Exception:
            return False

    def calculate_pressure(self, s):

        score = 0
        if s["suspicious_ua"]: score += 55
        if s["tor_exit"]: score += 45
        if s["high_rate"]: score += 45
        if s["sensitive_probe"]: score += 65
        if s["payload_attack"]: score += 90
        if s["known_bad_ip"]: score += 100
        return min(score,400)


class DeviceFingerprint:

    @staticmethod
    def assess(req):

        headers = req.get("headers",{})

        plugin_hash = hashlib.sha256(
            json.dumps(sorted(headers.get("plugins",[]))).encode()
        ).hexdigest()[:10]

        font_hash = hashlib.sha256(
            json.dumps(sorted(headers.get("fonts",[]))).encode()
        ).hexdigest()[:10]

        return {

            "entropy_score": len(headers) + random.randint(20,50),

            "headless":
                any(x in str(headers).lower()
                    for x in ["headless","selenium","puppeteer"]),

            "canvas_id": secrets.token_hex(10),

            "plugins_hash":plugin_hash,

            "fonts_hash":font_hash
        }


class NetworkPathAnalyzer:

    @staticmethod
    def analyze(req):

        ip = req.get("source_ip","0.0.0.0")

        latency = req.get("latency_ms",random.randint(5,500))

        return {

            "proxy_score": 90 if ip.startswith("185.") else 25,

            "latency": latency,

            "latency_anomaly": latency > 400,

            "asn_reputation": 80 if ip.startswith("45.") else 30
        }


class RiskEngine:

    @staticmethod
    def compute(obs):

        p = obs["attacker"]["pressure_score"]
        f = obs["fingerprint"]["entropy_score"]
        n = obs["network"]["proxy_score"]
        l = 45 if obs["network"]["latency_anomaly"] else 0

        score = p*1.3 + f*0.6 + n*0.8 + l

        if obs["fingerprint"]["headless"]:
            score += 90

        return round(min(score,600),1)


class DecisionEngine:

    @staticmethod
    def decide(score):

        if score > 400: return "block"
        if score > 300: return "contain"
        if score > 200: return "challenge"
        if score > 100: return "monitor"
        if score > 50: return "log"
        return "allow"


class DetectionEngine:

    def __init__(self):

        self.running = False

        self.events = []

        self.queue = Queue()

        self.collector = AttackerSignalCollector()

        self.lock = threading.Lock()

        self.request_counts = {}

        self.rate_window = 60

    def update_rate(self, ip):

        now = time.time()

        with self.lock:

            if ip not in self.request_counts:
                self.request_counts[ip] = (1,now)
                return 1

            count,ts = self.request_counts[ip]

            if now - ts > self.rate_window:
                count = 1
                ts = now
            else:
                count += 1

            self.request_counts[ip] = (count,ts)
            return count

    def process(self, req):

        ip = req.get("source_ip","0.0.0.0")

        req["requests_last_minute"] = self.update_rate(ip)

        attacker = self.collector.assess_request(req)

        fingerprint = DeviceFingerprint.assess(req)

        network = NetworkPathAnalyzer.analyze(req)

        observation = {

            "time": datetime.now(timezone.utc).isoformat(),

            "attacker": attacker,

            "fingerprint": fingerprint,

            "network": network,

            "summary": {
                k:v for k,v in req.items()
                if k in ["method","uri","source_ip","user_agent"]
            }
        }

        score = RiskEngine.compute(observation)

        decision = DecisionEngine.decide(score)

        event = {
            "observation":observation,
            "risk_score":score,
            "decision":decision
        }

        with self.lock:
            self.events.append(event)
            if len(self.events) > 1000:
                self.events.pop(0)

        logger.info(f"{decision.upper():<10} score={score} ip={ip}")

        return event

    def worker(self):

        while self.running:

            try:
                req = self.queue.get(timeout=2)
                self.process(req)
            except Empty:
                pass

    def start(self,threads=4):

        if self.running:
            return

        self.running = True

        for _ in range(threads):
            threading.Thread(target=self.worker,daemon=True).start()

    def stop(self):
        self.running = False

    def submit(self,req):
        self.queue.put(req)


class ControlServer(BaseHTTPRequestHandler):

    engine = DetectionEngine()

    def do_GET(self):

        if self.path == "/status":

            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.end_headers()

            data = {
                "running":self.engine.running,
                "events":len(self.engine.events),
                "queue":self.engine.queue.qsize()
            }

            self.wfile.write(json.dumps(data).encode())
            return

        if self.path == "/events":

            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.end_headers()

            self.wfile.write(json.dumps(self.engine.events).encode())
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):

        length = int(self.headers.get("Content-Length",0))
        body = self.rfile.read(length)

        if self.path == "/start":
            self.engine.start()
            self.send_response(200)
            self.end_headers()
            return

        if self.path == "/stop":
            self.engine.stop()
            self.send_response(200)
            self.end_headers()
            return

        if self.path == "/process":

            req = json.loads(body)

            result = self.engine.process(req)

            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.end_headers()

            self.wfile.write(json.dumps(result).encode())
            return

        if self.path == "/submit":

            req = json.loads(body)

            self.engine.submit(req)

            self.send_response(202)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()


def run():

    server = HTTPServer(("0.0.0.0",4789),ControlServer)

    logger.info("Server listening on :4789")

    server.serve_forever()


if __name__ == "__main__":
    run()
