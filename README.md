# DefensiveSkeletonFramework

Lightweight behavioral threat detection and request risk scoring engine.

Features
- HTTP request anomaly detection
- User-agent threat intelligence checks
- Payload attack pattern detection
- Rate anomaly detection
- Device fingerprint entropy analysis
- Network path risk scoring
- Adaptive decision engine

Architecture

Request
   ↓
Signal Collection
   ↓
Device Fingerprint Analysis
   ↓
Network Path Analysis
   ↓
Risk Scoring Engine
   ↓
Decision Engine
   ↓
Event Log / Response

API

POST /start
Start worker threads.

POST /stop
Stop analysis engine.

POST /process
Submit a request object for immediate scoring.

POST /submit
Queue request for async analysis.

GET /status
Engine runtime state.

GET /events
Return stored detection events.

Example Request

{
 "method":"GET",
 "uri":"/.env",
 "source_ip":"185.220.101.12",
 "user_agent":"sqlmap",
 "headers":{}
}

Run

python DefensiveOffense.py

Server will start on port 4789.
