#!/bin/bash
# ============================================================
# AWS Lightsail Deployment Script for Relay Platform
# ============================================================
# 
# Usage:
#   1. SSH into your fresh Ubuntu 22.04 Instance
#   2. Run: sudo bash setup.sh
#
# ============================================================

set -e  # Exit on any error

echo "============================================================"
echo "🚀 Relay Platform - Lightsail Deployment"
echo "============================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run with sudo: sudo bash setup.sh${NC}"
    exit 1
fi

APP_DIR="/opt/relay-platform"

# ============================================================
# Step 1: System Updates
# ============================================================
echo -e "${YELLOW}[1/8] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

# ============================================================
# Step 2: Install Dependencies
# ============================================================
echo -e "${YELLOW}[2/8] Installing dependencies...${NC}"

# Python
apt-get install -y python3.11 python3.11-venv python3-pip

# Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Nginx & Certbot
apt-get install -y nginx certbot python3-certbot-nginx

# Utilities
apt-get install -y git curl wget unzip htop

echo -e "${GREEN}✓ Dependencies installed${NC}"

# ============================================================
# Step 3: Install AWS CLI
# ============================================================
echo -e "${YELLOW}[3/8] Installing AWS CLI...${NC}"

if ! command -v aws &> /dev/null; then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    ./aws/install
    rm -rf aws awscliv2.zip
fi

echo -e "${GREEN}✓ AWS CLI installed${NC}"

# ============================================================
# Step 4: Create Directory Structure
# ============================================================
echo -e "${YELLOW}[4/8] Setting up directories...${NC}"

mkdir -p $APP_DIR
cd $APP_DIR
mkdir -p backend frontend data logs

# ============================================================
# Step 5: Backend Setup
# ============================================================
echo -e "${YELLOW}[5/8] Creating Backend...${NC}"

# Virtual Env
python3.11 -m venv $APP_DIR/venv
source $APP_DIR/venv/bin/activate

# Install Python Deps
pip install --upgrade pip
pip install fastapi uvicorn[standard] sqlalchemy python-jose[cryptography] \
    passlib[bcrypt] python-multipart boto3 aiohttp requests pydantic[email]

# --- models.py ---
cat > $APP_DIR/backend/models.py << 'MODELS_PY'
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Enum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import enum

Base = declarative_base()

class InstanceStatus(enum.Enum):
    PENDING = "pending"
    LAUNCHING = "launching"
    INITIALIZING = "initializing"
    READY = "ready"
    SENDING = "sending"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    ERROR = "error"

class EmailStatus(enum.Enum):
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    instances = relationship("RelayInstance", back_populates="owner")
    emails = relationship("EmailRecord", back_populates="sender")

class RelayInstance(Base):
    __tablename__ = "relay_instances"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    instance_id = Column(String(50), unique=True, nullable=True, index=True)
    public_ip = Column(String(50), nullable=True)
    region = Column(String(20), nullable=False)
    instance_type = Column(String(20), default="t3.micro")
    status = Column(Enum(InstanceStatus), default=InstanceStatus.PENDING)
    status_message = Column(String(500), nullable=True)
    name = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    ready_at = Column(DateTime, nullable=True)
    terminated_at = Column(DateTime, nullable=True)
    emails_sent = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)
    owner = relationship("User", back_populates="instances")
    emails = relationship("EmailRecord", back_populates="instance")

class EmailRecord(Base):
    __tablename__ = "email_records"
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    instance_id = Column(Integer, ForeignKey("relay_instances.id"), nullable=True)
    from_address = Column(String(100), nullable=False)
    to_address = Column(String(100), nullable=False)
    subject = Column(String(500), nullable=False)
    body_preview = Column(String(500), nullable=True)
    status = Column(Enum(EmailStatus), default=EmailStatus.QUEUED)
    error_message = Column(Text, nullable=True)
    relay_ip = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    sent_at = Column(DateTime, nullable=True)
    sender = relationship("User", back_populates="emails")
    instance = relationship("RelayInstance", back_populates="emails")

def init_database(db_path="/opt/relay-platform/data/relay.db"):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return engine

def get_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)
MODELS_PY

# --- auth.py ---
cat > $APP_DIR/backend/auth.py << 'AUTH_PY'
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
import os

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
AUTH_PY

# --- aws_service.py ---
cat > $APP_DIR/backend/aws_service.py << 'AWS_PY'
import boto3, asyncio, aiohttp, logging, requests
from typing import Optional
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)
executor = ThreadPoolExecutor(max_workers=10)

@dataclass
class InstanceInfo:
    instance_id: str
    public_ip: Optional[str]
    region: str
    state: str
    launch_time: Optional[datetime] = None

# Script that runs ON the EC2 instance
USER_DATA_SCRIPT = '''#!/bin/bash
set -e
exec > >(tee /var/log/user-data.log) 2>&1
dnf update -y
dnf install -y python3.11 python3.11-pip
mkdir -p /opt/relay-agent && cd /opt/relay-agent
python3.11 -m pip install fastapi uvicorn

cat > /opt/relay-agent/main.py << 'PYCODE'
import smtplib, ssl, socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

class EmailPayload(BaseModel):
    smtp_user: str
    smtp_pass: str
    to_address: str
    subject: str
    body: str
    html_body: Optional[str] = None

@app.get("/health")
async def health():
    return {"status": "healthy", "hostname": socket.gethostname()}

@app.post("/send")
async def send_email(p: EmailPayload):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"], msg["From"], msg["To"] = p.subject, p.smtp_user, p.to_address
        msg.attach(MIMEText(p.body, "plain"))
        if p.html_body: msg.attach(MIMEText(p.html_body, "html"))
        ctx = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.starttls(context=ctx)
            s.login(p.smtp_user, p.smtp_pass)
            s.sendmail(p.smtp_user, p.to_address, msg.as_string())
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, str(e))
PYCODE

cat > /etc/systemd/system/relay-agent.service << 'SVC'
[Unit]
Description=Relay Agent
After=network.target
[Service]
Type=simple
WorkingDirectory=/opt/relay-agent
ExecStart=/usr/bin/python3.11 -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload && systemctl enable relay-agent && systemctl start relay-agent
'''

class AWSRelayService:
    INSTANCE_TYPE = "t3.micro"
    SG_NAME = "relay-platform-sg"

    def __init__(self, region="us-east-1"):
        self.region = region
        self.session = boto3.Session(region_name=region)
        self.ec2 = self.session.client('ec2')
        self.ssm = self.session.client('ssm')

    @staticmethod
    def get_regions():
        return ['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1','eu-central-1','ap-south-1','ap-southeast-1']

    def get_my_ip(self):
        for svc in ['https://api.ipify.org','https://ifconfig.me/ip']:
            try:
                r = requests.get(svc, timeout=5)
                if r.ok: return r.text.strip()
            except: pass
        raise RuntimeError("Could not get IP")

    def _get_ami(self):
        try:
            return self.ssm.get_parameter(Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64')['Parameter']['Value']
        except:
            imgs = self.ec2.describe_images(Owners=['amazon'], Filters=[{'Name':'name','Values':['al2023-ami-2023*-x86_64']},{'Name':'state','Values':['available']}])['Images']
            return sorted(imgs, key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']

    def _ensure_sg(self, ip):
        cidr = f"{ip}/32"
        try:
            sgs = self.ec2.describe_security_groups(Filters=[{'Name':'group-name','Values':[self.SG_NAME]}])['SecurityGroups']
            if sgs: return sgs[0]['GroupId']
        except: pass
        vpc = self.ec2.describe_vpcs(Filters=[{'Name':'is-default','Values':['true']}])['Vpcs'][0]['VpcId']
        sg_id = self.ec2.create_security_group(GroupName=self.SG_NAME, Description="Relay SG", VpcId=vpc)['GroupId']
        self.ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
            {'IpProtocol':'tcp','FromPort':8000,'ToPort':8000,'IpRanges':[{'CidrIp':cidr}]},
            {'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[{'CidrIp':cidr}]}
        ])
        return sg_id

    def launch(self, name=None):
        ip = self.get_my_ip()
        ami = self._get_ami()
        sg = self._ensure_sg(ip)
        resp = self.ec2.run_instances(
            ImageId=ami, InstanceType=self.INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SecurityGroupIds=[sg], UserData=USER_DATA_SCRIPT,
            TagSpecifications=[{'ResourceType':'instance','Tags':[{'Key':'Name','Value':name or 'Relay'},{'Key':'Platform','Value':'RelayPlatform'}]}]
        )
        iid = resp['Instances'][0]['InstanceId']
        self.ec2.get_waiter('instance_running').wait(InstanceIds=[iid])
        info = self.ec2.describe_instances(InstanceIds=[iid])['Reservations'][0]['Instances'][0]
        return InstanceInfo(iid, info.get('PublicIpAddress'), self.region, info['State']['Name'], info.get('LaunchTime'))

    def terminate(self, iid):
        try:
            self.ec2.terminate_instances(InstanceIds=[iid])
            return True
        except: return False

class RelayClient:
    def __init__(self, url):
        self.url = url.rstrip('/')

    async def health(self):
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(f"{self.url}/health") as r:
                    return await r.json() if r.status == 200 else {"status":"error"}
        except: return {"status":"unreachable"}

    async def send(self, smtp_user, smtp_pass, to, subject, body, html=None):
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
                # Correct payload keys matching Agent
                async with s.post(f"{self.url}/send", json={"smtp_user":smtp_user,"smtp_pass":smtp_pass,"to_address":to,"subject":subject,"body":body,"html_body":html}) as r:
                    return await r.json()
        except Exception as e: return {"success":False,"error":str(e)}

    async def wait_ready(self, timeout=180):
        import time
        start = time.time()
        while time.time() - start < timeout:
            h = await self.health()
            if h.get("status") == "healthy": return True
            await asyncio.sleep(10)
        return False

async def async_launch(region, name=None):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, AWSRelayService(region).launch, name)

async def async_terminate(region, iid):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, AWSRelayService(region).terminate, iid)
AWS_PY

# --- main.py ---
cat > $APP_DIR/backend/main.py << 'MAIN_PY'
import asyncio, logging
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from models import User, RelayInstance, EmailRecord, InstanceStatus, EmailStatus, init_database, get_session_factory
from auth import verify_password, get_password_hash, create_access_token, decode_token
from aws_service import AWSRelayService, RelayClient, async_launch, async_terminate

logging.basicConfig(level=logging.INFO)
engine = init_database()
SessionFactory = get_session_factory(engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionFactory()
    if not db.query(User).filter(User.is_admin==True).first():
        db.add(User(username="admin", email="admin@localhost", hashed_password=get_password_hash("admin123"), is_admin=True))
        db.commit()
    db.close()
    yield

app = FastAPI(title="Relay Platform", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_db():
    db = SessionFactory()
    try: yield db
    finally: db.close()

async def get_user(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    data = decode_token(token)
    if not data: raise HTTPException(401, "Invalid token")
    user = db.query(User).filter(User.username == data.get("sub")).first()
    if not user: raise HTTPException(401, "User not found")
    return user

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class InstanceCreate(BaseModel):
    region: str = "us-east-1"
    name: Optional[str] = None

class EmailSend(BaseModel):
    instance_id: int
    smtp_user: str
    smtp_pass: str
    to_address: str
    subject: str
    body: str

@app.post("/auth/register")
async def register(data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username taken")
    user = User(username=data.username, email=data.email, hashed_password=get_password_hash(data.password))
    db.add(user)
    db.commit()
    return {"message": "Registered"}

@app.post("/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": user.username, "user_id": user.id})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/auth/me")
async def me(user: User = Depends(get_user)):
    return {"id": user.id, "username": user.username, "email": user.email, "is_admin": user.is_admin}

@app.get("/instances")
async def list_instances(user: User = Depends(get_user), db: Session = Depends(get_db)):
    instances = db.query(RelayInstance).filter(RelayInstance.owner_id == user.id, RelayInstance.status != InstanceStatus.TERMINATED).all()
    return [{"id":i.id,"instance_id":i.instance_id,"public_ip":i.public_ip,"region":i.region,"status":i.status.value,"status_message":i.status_message,"name":i.name,"created_at":i.created_at.isoformat(),"emails_sent":i.emails_sent} for i in instances]

@app.post("/instances")
async def create_instance(data: InstanceCreate, bg: BackgroundTasks, user: User = Depends(get_user), db: Session = Depends(get_db)):
    inst = RelayInstance(owner_id=user.id, region=data.region, name=data.name, status=InstanceStatus.PENDING)
    db.add(inst)
    db.commit()
    db.refresh(inst)
    bg.add_task(launch_task, inst.id, data.region, data.name)
    return {"id": inst.id, "status": "pending"}

async def launch_task(inst_id, region, name):
    db = SessionFactory()
    try:
        inst = db.query(RelayInstance).filter(RelayInstance.id == inst_id).first()
        inst.status = InstanceStatus.LAUNCHING
        db.commit()
        info = await async_launch(region, name)
        inst.instance_id = info.instance_id
        inst.public_ip = info.public_ip
        inst.status = InstanceStatus.INITIALIZING
        db.commit()
        if info.public_ip:
            client = RelayClient(f"http://{info.public_ip}:8000")
            if await client.wait_ready(180):
                inst.status = InstanceStatus.READY
                inst.ready_at = datetime.utcnow()
            else:
                inst.status = InstanceStatus.ERROR
                inst.status_message = "Agent timeout"
        db.commit()
    except Exception as e:
        inst.status = InstanceStatus.ERROR
        inst.status_message = str(e)
        db.commit()
    finally:
        db.close()

@app.delete("/instances/{id}")
async def delete_instance(id: int, bg: BackgroundTasks, user: User = Depends(get_user), db: Session = Depends(get_db)):
    inst = db.query(RelayInstance).filter(RelayInstance.id == id, RelayInstance.owner_id == user.id).first()
    if not inst: raise HTTPException(404)
    inst.status = InstanceStatus.TERMINATING
    db.commit()
    bg.add_task(terminate_task, inst.id, inst.region, inst.instance_id)
    return {"message": "Terminating"}

async def terminate_task(inst_id, region, aws_id):
    db = SessionFactory()
    try:
        inst = db.query(RelayInstance).filter(RelayInstance.id == inst_id).first()
        if aws_id: await async_terminate(region, aws_id)
        inst.status = InstanceStatus.TERMINATED
        inst.terminated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

@app.get("/instances/{id}/health")
async def instance_health(id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    inst = db.query(RelayInstance).filter(RelayInstance.id == id, RelayInstance.owner_id == user.id).first()
    if not inst or not inst.public_ip: raise HTTPException(404)
    return await RelayClient(f"http://{inst.public_ip}:8000").health()

@app.post("/emails/send")
async def send_email(data: EmailSend, user: User = Depends(get_user), db: Session = Depends(get_db)):
    inst = db.query(RelayInstance).filter(RelayInstance.id == data.instance_id, RelayInstance.owner_id == user.id).first()
    if not inst or inst.status != InstanceStatus.READY: raise HTTPException(400, "Instance not ready")
    rec = EmailRecord(sender_id=user.id, instance_id=inst.id, from_address=data.smtp_user, to_address=data.to_address, subject=data.subject, status=EmailStatus.SENDING, relay_ip=inst.public_ip)
    db.add(rec)
    db.commit()
    result = await RelayClient(f"http://{inst.public_ip}:8000").send(data.smtp_user, data.smtp_pass, data.to_address, data.subject, data.body)
    rec.status = EmailStatus.SENT if result.get("success") else EmailStatus.FAILED
    rec.error_message = result.get("error") or result.get("detail")
    if rec.status == EmailStatus.SENT:
        rec.sent_at = datetime.utcnow()
        inst.emails_sent += 1
    db.commit()
    return {"success": rec.status == EmailStatus.SENT, "error": rec.error_message}

@app.get("/emails")
async def list_emails(user: User = Depends(get_user), db: Session = Depends(get_db)):
    emails = db.query(EmailRecord).filter(EmailRecord.sender_id == user.id).order_by(EmailRecord.created_at.desc()).limit(50).all()
    return [{"id":e.id,"to_address":e.to_address,"subject":e.subject,"status":e.status.value,"relay_ip":e.relay_ip,"created_at":e.created_at.isoformat(),"sent_at":e.sent_at.isoformat() if e.sent_at else None,"error_message":e.error_message} for e in emails]

@app.get("/regions")
async def regions():
    return AWSRelayService.get_regions()

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
MAIN_PY

echo -e "${GREEN}✓ Backend Created${NC}"

# ============================================================
# Step 6: Create Frontend (FIXED REACT CODE)
# ============================================================
echo -e "${YELLOW}[6/8] Building frontend...${NC}"

cd $APP_DIR/frontend

# package.json
cat > package.json << 'PKG'
{
  "name": "relay-frontend",
  "version": "1.0.0",
  "scripts": {
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.0",
    "vite": "^5.0.0"
  }
}
PKG

# vite.config.js
cat > vite.config.js << 'VITE'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist' }
})
VITE

# index.html
cat > index.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Relay Platform</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.jsx"></script>
</body>
</html>
HTML

mkdir -p src

# main.jsx
cat > src/main.jsx << 'MAINJS'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
ReactDOM.createRoot(document.getElementById('root')).render(<App />)
MAINJS

# --- App.jsx (CORRECTED VERSION) ---
cat > src/App.jsx << 'APPJS'
import React, { useState, useEffect, useCallback } from 'react';
const API = '';
const api = {
  token: localStorage.getItem('token'),
  setToken(t) { this.token = t; t ? localStorage.setItem('token', t) : localStorage.removeItem('token'); },
  async req(url, opt = {}) {
    const r = await fetch(API + url, { ...opt, headers: { 'Content-Type': 'application/json', ...(this.token && { Authorization: `Bearer ${this.token}` }), ...opt.headers } });
    if (r.status === 401) { this.setToken(null); location.reload(); }
    const d = await r.json();
    if (!r.ok) {
       if (r.status === 422 && Array.isArray(d.detail)) throw new Error(d.detail.map(e => `${e.loc[1]}: ${e.msg}`).join('\n'));
       throw new Error(d.detail || 'Error');
    }
    return d;
  }
};

function Auth({ onLogin }) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      if (isLogin) {
        const d = await api.req('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ username, password }) });
        api.setToken(d.access_token);
      } else {
        await api.req('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password }) });
        const d = await api.req('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ username, password }) });
        api.setToken(d.access_token);
      }
      onLogin();
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg w-full max-w-md">
        <h1 className="text-2xl font-bold text-white mb-6 text-center">📧 Relay Platform</h1>
        <div className="flex mb-6">
          <button onClick={() => setIsLogin(true)} className={`flex-1 py-2 rounded-l ${isLogin ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'}`}>Login</button>
          <button onClick={() => setIsLogin(false)} className={`flex-1 py-2 rounded-r ${!isLogin ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400'}`}>Register</button>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} className="w-full p-3 bg-gray-700 text-white rounded" required />
          {!isLogin && <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} className="w-full p-3 bg-gray-700 text-white rounded" required />}
          <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} className="w-full p-3 bg-gray-700 text-white rounded" required />
          {error && <div className="text-red-400 text-sm">{error}</div>}
          <button type="submit" disabled={loading} className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50">{loading ? 'Loading...' : (isLogin ? 'Login' : 'Register')}</button>
        </form>
        <p className="text-gray-500 text-sm text-center mt-4">Default: admin / admin123</p>
      </div>
    </div>
  );
}

function Dashboard({ user, onLogout }) {
  const [instances, setInstances] = useState([]);
  const [emails, setEmails] = useState([]);
  const [regions, setRegions] = useState([]);
  const [selected, setSelected] = useState(null);
  const [region, setRegion] = useState('us-east-1');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [smtp, setSmtp] = useState({ smtp_user: '', smtp_pass: '', to_address: '', subject: '', body: '' });
  const [sendResult, setSendResult] = useState(null);

  const load = useCallback(async () => {
    try {
        const [i, e, r] = await Promise.all([api.req('/instances'), api.req('/emails'), api.req('/regions')]);
        setInstances(i);
        setEmails(e);
        setRegions(r);
    } catch(err) { console.error(err); }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);

  const launch = async () => {
    setLoading(true);
    try {
      await api.req('/instances', { method: 'POST', body: JSON.stringify({ region, name: name || undefined }) });
      setName('');
      load();
    } catch (e) { alert(e.message); }
    setLoading(false);
  };

  const terminate = async (id) => {
    if (!confirm('Terminate?')) return;
    await api.req(`/instances/${id}`, { method: 'DELETE' });
    load();
  };

  const send = async (e) => {
    e.preventDefault();
    if (!selected) return;
    setSendResult(null);
    try {
        const r = await api.req('/emails/send', { method: 'POST', body: JSON.stringify({ instance_id: parseInt(selected.id), ...smtp }) });
        setSendResult(r);
        if (r.success) { 
            setSmtp({ ...smtp, to_address: '', subject: '', body: '' }); 
            load(); 
        }
    } catch(e) {
        setSendResult({ success: false, error: e.message });
    }
  };

  const colors = { pending: 'bg-yellow-500', launching: 'bg-yellow-500', initializing: 'bg-yellow-500', ready: 'bg-green-500', error: 'bg-red-500', terminating: 'bg-orange-500' };

  return (
    <div className="min-h-screen bg-gray-900">
      <header className="bg-gray-800 border-b border-gray-700 p-4 flex justify-between items-center">
        <h1 className="text-xl font-bold text-white">📧 Relay Platform</h1>
        <div className="flex items-center gap-4">
          <span className="text-gray-400">👤 {user.username}</span>
          <button onClick={onLogout} className="px-3 py-1 bg-gray-700 text-white rounded text-sm">Logout</button>
        </div>
      </header>
      <main className="max-w-7xl mx-auto p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-4">🚀 Launch Relay</h2>
            <div className="flex gap-4">
              <select value={region} onChange={e => setRegion(e.target.value)} className="flex-1 p-3 bg-gray-700 text-white rounded">{regions.map(r => <option key={r}>{r}</option>)}</select>
              <input placeholder="Name (optional)" value={name} onChange={e => setName(e.target.value)} className="flex-1 p-3 bg-gray-700 text-white rounded" />
              <button onClick={launch} disabled={loading} className="px-6 py-3 bg-blue-600 text-white rounded disabled:opacity-50">{loading ? '...' : '🚀 Launch'}</button>
            </div>
          </div>
          <h2 className="text-xl font-bold text-white">📡 Instances ({instances.length})</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {instances.map(i => (
              <div key={i.id} onClick={() => i.status === 'ready' && setSelected(i)} className={`bg-gray-800 rounded-lg p-4 cursor-pointer border-2 ${selected?.id === i.id ? 'border-blue-500' : 'border-transparent hover:border-gray-600'}`}>
                <div className="flex justify-between mb-2">
                  <span className="text-white font-medium">{i.name || `#${i.id}`}</span>
                  <span className={`px-2 py-1 rounded text-xs text-white ${colors[i.status] || 'bg-gray-500'}`}>{i.status}</span>
                </div>
                <div className="text-sm text-gray-400 space-y-1">
                  <div>IP: <span className="text-white font-mono">{i.public_ip || '—'}</span></div>
                  <div>Region: {i.region} | Sent: {i.emails_sent}</div>
                </div>
                {i.status !== 'terminated' && <button onClick={(e) => { e.stopPropagation(); terminate(i.id); }} className="mt-3 w-full py-1 bg-red-600 text-white text-sm rounded">Terminate</button>}
              </div>
            ))}
          </div>
        </div>
        <div className="space-y-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-bold text-white mb-4">✉️ Send Email</h2>
            {!selected ? <p className="text-gray-400">Select a ready instance</p> : (
              <form onSubmit={send} className="space-y-3">
                <input placeholder="Gmail" value={smtp.smtp_user} onChange={e => setSmtp({ ...smtp, smtp_user: e.target.value })} className="w-full p-2 bg-gray-700 text-white rounded text-sm" required />
                <input type="password" placeholder="App Password" value={smtp.smtp_pass} onChange={e => setSmtp({ ...smtp, smtp_pass: e.target.value })} className="w-full p-2 bg-gray-700 text-white rounded text-sm" required />
                <input placeholder="To" value={smtp.to_address} onChange={e => setSmtp({ ...smtp, to_address: e.target.value })} className="w-full p-2 bg-gray-700 text-white rounded text-sm" required />
                <input placeholder="Subject" value={smtp.subject} onChange={e => setSmtp({ ...smtp, subject: e.target.value })} className="w-full p-2 bg-gray-700 text-white rounded text-sm" required />
                <textarea placeholder="Body" value={smtp.body} onChange={e => setSmtp({ ...smtp, body: e.target.value })} rows={3} className="w-full p-2 bg-gray-700 text-white rounded text-sm" required />
                {sendResult && <div className={sendResult.success ? 'text-green-400' : 'text-red-400'}>{sendResult.success ? '✓ Sent!' : sendResult.error}</div>}
                <button className="w-full py-2 bg-blue-600 text-white rounded">📤 Send</button>
              </form>
            )}
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-bold text-white mb-4">📜 History</h2>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {emails.slice(0, 10).map(e => (
                <div key={e.id} className="bg-gray-700 rounded p-2 text-sm">
                  <div className="flex justify-between"><span className="text-white truncate">{e.subject}</span><span className={e.status === 'sent' ? 'text-green-400' : 'text-red-400'}>{e.status}</span></div>
                  <div className="text-gray-400 text-xs">{e.to_address} • {e.relay_ip}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      if (api.token) {
        try { setUser(await api.req('/auth/me')); } catch { api.setToken(null); }
      }
      setLoading(false);
    })();
  }, []);

  if (loading) return <div className="min-h-screen flex items-center justify-center bg-gray-900 text-white">Loading...</div>;
  if (!user) return <Auth onLogin={async () => setUser(await api.req('/auth/me'))} />;
  return <Dashboard user={user} onLogout={() => { api.setToken(null); setUser(null); }} />;
}
APPJS

# Install and build
npm install
npm run build

echo -e "${GREEN}✓ Frontend built${NC}"

# ============================================================
# Step 7: Configure Nginx
# ============================================================
echo -e "${YELLOW}[7/8] Configuring Nginx...${NC}"

cat > /etc/nginx/sites-available/relay-platform << 'NGINX'
server {
    listen 80;
    server_name _;
    
    # Frontend
    location / {
        root /opt/relay-platform/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
    
    # API proxy
    location ~ ^/(auth|instances|emails|regions|health) {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/relay-platform /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

echo -e "${GREEN}✓ Nginx configured${NC}"

# ============================================================
# Step 8: Create Systemd Service
# ============================================================
echo -e "${YELLOW}[8/8] Creating systemd service...${NC}"

cat > /etc/systemd/system/relay-platform.service << 'SERVICE'
[Unit]
Description=Relay Platform API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/relay-platform/backend
Environment="PATH=/opt/relay-platform/venv/bin"
Environment="SECRET_KEY=change-this-to-a-secure-random-string"
ExecStart=/opt/relay-platform/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable relay-platform
systemctl start relay-platform

echo -e "${GREEN}✓ Service created and started${NC}"

# ============================================================
# Final Summary
# ============================================================
echo ""
echo "============================================================"
echo -e "${GREEN}🎉 Installation Complete!${NC}"
echo "============================================================"
echo ""
echo "Your Relay Platform is now running!"
echo ""
echo "  📍 URL: http://$(curl -s ifconfig.me)"
echo "  👤 Login: admin / admin123"
echo ""
echo "============================================================"
echo "IMPORTANT NEXT STEPS:"
echo "============================================================"
echo ""
echo "1. Configure AWS credentials:"
echo "   aws configure"
echo ""
echo "2. Change the SECRET_KEY in:"
echo "   /etc/systemd/system/relay-platform.service"
echo ""
echo "3. (Optional) Add SSL with Let's Encrypt:"
echo "   certbot --nginx"
echo "============================================================"