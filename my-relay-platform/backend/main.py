"""
Relay Platform - FastAPI Backend
=================================
Multi-user, multi-instance email relay management platform.

Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8080
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from models import (
    Base, User, RelayInstance, EmailRecord, SMTPConfig, AuditLog,
    InstanceStatus, EmailStatus, init_database, get_session_factory
)
from auth import (
    verify_password, get_password_hash, create_token_for_user,
    decode_token, Token, TokenData
)
from aws_service import (
    AWSRelayService, RelayAgentClient,
    async_launch_instance, async_terminate_instance, async_get_instance_status
)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
engine = init_database()
SessionFactory = get_session_factory(engine)

# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}  # user_id -> connections
    
    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
    
    def disconnect(self, websocket: WebSocket, user_id: int):
        if user_id in self.active_connections:
            self.active_connections[user_id].remove(websocket)
    
    async def send_to_user(self, user_id: int, message: dict):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                except:
                    pass
    
    async def broadcast(self, message: dict):
        for connections in self.active_connections.values():
            for connection in connections:
                try:
                    await connection.send_json(message)
                except:
                    pass

manager = ConnectionManager()

# App lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Relay Platform...")
    create_default_admin()
    yield
    # Shutdown
    logger.info("Shutting down Relay Platform...")

# FastAPI app
app = FastAPI(
    title="Relay Platform API",
    description="Multi-user email relay management platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# ============== Dependencies ==============

def get_db():
    """Database session dependency."""
    db = SessionFactory()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token_data = decode_token(token)
    if token_data is None:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    
    return user


# ============== Pydantic Schemas ==============

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class InstanceCreate(BaseModel):
    region: str = "us-east-1"
    name: Optional[str] = None


class InstanceResponse(BaseModel):
    id: int
    instance_id: Optional[str]
    public_ip: Optional[str]
    region: str
    status: str
    status_message: Optional[str]
    name: Optional[str]
    created_at: datetime
    emails_sent: int
    
    class Config:
        from_attributes = True


class EmailSend(BaseModel):
    instance_id: int
    smtp_config_id: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_pass: Optional[str] = None
    to_address: str
    subject: str
    body: str
    html_body: Optional[str] = None


class EmailResponse(BaseModel):
    id: int
    to_address: str
    subject: str
    status: str
    relay_ip: Optional[str]
    created_at: datetime
    sent_at: Optional[datetime]
    error_message: Optional[str]
    
    class Config:
        from_attributes = True


class SMTPConfigCreate(BaseModel):
    name: str
    smtp_user: str
    smtp_pass: str
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    is_default: bool = False


class SMTPConfigResponse(BaseModel):
    id: int
    name: str
    smtp_user: str
    smtp_host: str
    smtp_port: int
    is_default: bool
    
    class Config:
        from_attributes = True


# ============== Helper Functions ==============

def create_default_admin():
    """Create default admin user if none exists."""
    db = SessionFactory()
    try:
        admin = db.query(User).filter(User.is_admin == True).first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@localhost",
                hashed_password=get_password_hash("admin123"),
                is_admin=True
            )
            db.add(admin)
            db.commit()
            logger.info("Created default admin user (admin/admin123)")
    finally:
        db.close()


def log_audit(db: Session, user_id: int, action: str, resource_type: str = None, 
              resource_id: int = None, details: str = None):
    """Log an audit entry."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details
    )
    db.add(entry)
    db.commit()


# ============== Auth Endpoints ==============

@app.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    # Check if username exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(400, "Username already registered")
    
    # Check if email exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(400, "Email already registered")
    
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return user


@app.post("/auth/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login and get access token."""
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    return create_token_for_user(user.id, user.username)


@app.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return current_user


# ============== Instance Endpoints ==============

@app.get("/instances", response_model=List[InstanceResponse])
async def list_instances(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all instances for the current user."""
    instances = db.query(RelayInstance).filter(
        RelayInstance.owner_id == current_user.id,
        RelayInstance.status.notin_([InstanceStatus.TERMINATED])
    ).order_by(RelayInstance.created_at.desc()).all()
    
    return [InstanceResponse(
        id=i.id,
        instance_id=i.instance_id,
        public_ip=i.public_ip,
        region=i.region,
        status=i.status.value,
        status_message=i.status_message,
        name=i.name,
        created_at=i.created_at,
        emails_sent=i.emails_sent
    ) for i in instances]


@app.post("/instances", response_model=InstanceResponse)
async def create_instance(
    data: InstanceCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Launch a new relay instance."""
    # Create DB record
    instance = RelayInstance(
        owner_id=current_user.id,
        region=data.region,
        name=data.name,
        status=InstanceStatus.PENDING
    )
    db.add(instance)
    db.commit()
    db.refresh(instance)
    
    # Launch in background
    background_tasks.add_task(
        launch_instance_task,
        instance.id,
        data.region,
        data.name,
        current_user.id
    )
    
    log_audit(db, current_user.id, "instance_launch_started", "instance", instance.id)
    
    return InstanceResponse(
        id=instance.id,
        instance_id=instance.instance_id,
        public_ip=instance.public_ip,
        region=instance.region,
        status=instance.status.value,
        status_message=instance.status_message,
        name=instance.name,
        created_at=instance.created_at,
        emails_sent=instance.emails_sent
    )


async def launch_instance_task(instance_id: int, region: str, name: str, user_id: int):
    """Background task to launch an instance."""
    db = SessionFactory()
    try:
        instance = db.query(RelayInstance).filter(RelayInstance.id == instance_id).first()
        if not instance:
            return
        
        # Update status to launching
        instance.status = InstanceStatus.LAUNCHING
        instance.status_message = "Launching EC2 instance..."
        db.commit()
        
        await manager.send_to_user(user_id, {
            "type": "instance_update",
            "instance_id": instance_id,
            "status": "launching",
            "message": "Launching EC2 instance..."
        })
        
        # Launch the instance
        try:
            info = await async_launch_instance(region, name)
            
            instance.instance_id = info.instance_id
            instance.public_ip = info.public_ip
            instance.status = InstanceStatus.INITIALIZING
            instance.status_message = "Installing relay agent..."
            db.commit()
            
            await manager.send_to_user(user_id, {
                "type": "instance_update",
                "instance_id": instance_id,
                "status": "initializing",
                "public_ip": info.public_ip,
                "message": "Installing relay agent..."
            })
            
            # Wait for agent to be ready
            if info.public_ip:
                client = RelayAgentClient(f"http://{info.public_ip}:8000")
                ready = await client.wait_until_ready(timeout=180)
                
                if ready:
                    instance.status = InstanceStatus.READY
                    instance.status_message = "Ready to send emails"
                    instance.ready_at = datetime.utcnow()
                else:
                    instance.status = InstanceStatus.ERROR
                    instance.status_message = "Agent failed to start"
            
            db.commit()
            
            await manager.send_to_user(user_id, {
                "type": "instance_update",
                "instance_id": instance_id,
                "status": instance.status.value,
                "public_ip": instance.public_ip,
                "message": instance.status_message
            })
            
        except Exception as e:
            logger.error(f"Error launching instance: {e}")
            instance.status = InstanceStatus.ERROR
            instance.status_message = str(e)
            db.commit()
            
            await manager.send_to_user(user_id, {
                "type": "instance_update",
                "instance_id": instance_id,
                "status": "error",
                "message": str(e)
            })
    finally:
        db.close()


@app.delete("/instances/{instance_id}")
async def terminate_instance(
    instance_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Terminate a relay instance."""
    instance = db.query(RelayInstance).filter(
        RelayInstance.id == instance_id,
        RelayInstance.owner_id == current_user.id
    ).first()
    
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    if instance.status == InstanceStatus.TERMINATED:
        raise HTTPException(400, "Instance already terminated")
    
    instance.status = InstanceStatus.TERMINATING
    db.commit()
    
    # Terminate in background
    background_tasks.add_task(
        terminate_instance_task,
        instance.id,
        instance.region,
        instance.instance_id,
        current_user.id
    )
    
    log_audit(db, current_user.id, "instance_terminate_started", "instance", instance.id)
    
    return {"message": "Termination started"}


async def terminate_instance_task(db_id: int, region: str, aws_instance_id: str, user_id: int):
    """Background task to terminate an instance."""
    db = SessionFactory()
    try:
        instance = db.query(RelayInstance).filter(RelayInstance.id == db_id).first()
        if not instance:
            return
        
        if aws_instance_id:
            await async_terminate_instance(region, aws_instance_id)
        
        instance.status = InstanceStatus.TERMINATED
        instance.terminated_at = datetime.utcnow()
        instance.status_message = "Instance terminated"
        db.commit()
        
        await manager.send_to_user(user_id, {
            "type": "instance_update",
            "instance_id": db_id,
            "status": "terminated",
            "message": "Instance terminated"
        })
    finally:
        db.close()


@app.get("/instances/{instance_id}/health")
async def check_instance_health(
    instance_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Check health of a relay instance."""
    instance = db.query(RelayInstance).filter(
        RelayInstance.id == instance_id,
        RelayInstance.owner_id == current_user.id
    ).first()
    
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    if not instance.public_ip:
        return {"status": "no_ip", "message": "Instance has no public IP"}
    
    client = RelayAgentClient(f"http://{instance.public_ip}:8000")
    health = await client.health_check()
    
    return health


# ============== Email Endpoints ==============

@app.post("/emails/send", response_model=EmailResponse)
async def send_email(
    data: EmailSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send an email through a relay instance."""
    # Get instance
    instance = db.query(RelayInstance).filter(
        RelayInstance.id == data.instance_id,
        RelayInstance.owner_id == current_user.id
    ).first()
    
    if not instance:
        raise HTTPException(404, "Instance not found")
    
    if instance.status != InstanceStatus.READY:
        raise HTTPException(400, f"Instance not ready. Status: {instance.status.value}")
    
    # Get SMTP credentials
    smtp_user = data.smtp_user
    smtp_pass = data.smtp_pass
    
    if data.smtp_config_id:
        config = db.query(SMTPConfig).filter(
            SMTPConfig.id == data.smtp_config_id,
            SMTPConfig.owner_id == current_user.id
        ).first()
        if config:
            smtp_user = config.smtp_user
            # In production, decrypt the password here
            smtp_pass = config.smtp_pass_encrypted
    
    if not smtp_user or not smtp_pass:
        raise HTTPException(400, "SMTP credentials required")
    
    # Create email record
    email_record = EmailRecord(
        sender_id=current_user.id,
        instance_id=instance.id,
        from_address=smtp_user,
        to_address=data.to_address,
        subject=data.subject,
        body_preview=data.body[:500] if data.body else None,
        status=EmailStatus.SENDING,
        relay_ip=instance.public_ip
    )
    db.add(email_record)
    db.commit()
    db.refresh(email_record)
    
    # Send email
    client = RelayAgentClient(f"http://{instance.public_ip}:8000")
    result = await client.send_email(
        smtp_user=smtp_user,
        smtp_pass=smtp_pass,
        to_address=data.to_address,
        subject=data.subject,
        body=data.body,
        html_body=data.html_body
    )
    
    # Update record
    if result.get("success"):
        email_record.status = EmailStatus.SENT
        email_record.sent_at = datetime.utcnow()
        instance.emails_sent += 1
        instance.last_used_at = datetime.utcnow()
    else:
        email_record.status = EmailStatus.FAILED
        email_record.error_message = result.get("detail") or result.get("error")
    
    db.commit()
    db.refresh(email_record)
    
    log_audit(db, current_user.id, "email_sent", "email", email_record.id)
    
    return EmailResponse(
        id=email_record.id,
        to_address=email_record.to_address,
        subject=email_record.subject,
        status=email_record.status.value,
        relay_ip=email_record.relay_ip,
        created_at=email_record.created_at,
        sent_at=email_record.sent_at,
        error_message=email_record.error_message
    )


@app.get("/emails", response_model=List[EmailResponse])
async def list_emails(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List recent emails."""
    emails = db.query(EmailRecord).filter(
        EmailRecord.sender_id == current_user.id
    ).order_by(EmailRecord.created_at.desc()).limit(limit).all()
    
    return [EmailResponse(
        id=e.id,
        to_address=e.to_address,
        subject=e.subject,
        status=e.status.value,
        relay_ip=e.relay_ip,
        created_at=e.created_at,
        sent_at=e.sent_at,
        error_message=e.error_message
    ) for e in emails]


# ============== SMTP Config Endpoints ==============

@app.get("/smtp-configs", response_model=List[SMTPConfigResponse])
async def list_smtp_configs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List saved SMTP configurations."""
    configs = db.query(SMTPConfig).filter(
        SMTPConfig.owner_id == current_user.id
    ).all()
    return configs


@app.post("/smtp-configs", response_model=SMTPConfigResponse)
async def create_smtp_config(
    data: SMTPConfigCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Save a new SMTP configuration."""
    # In production, encrypt the password
    config = SMTPConfig(
        owner_id=current_user.id,
        name=data.name,
        smtp_user=data.smtp_user,
        smtp_pass_encrypted=data.smtp_pass,  # Should be encrypted
        smtp_host=data.smtp_host,
        smtp_port=data.smtp_port,
        is_default=data.is_default
    )
    
    if data.is_default:
        # Unset other defaults
        db.query(SMTPConfig).filter(
            SMTPConfig.owner_id == current_user.id,
            SMTPConfig.is_default == True
        ).update({"is_default": False})
    
    db.add(config)
    db.commit()
    db.refresh(config)
    
    return config


@app.delete("/smtp-configs/{config_id}")
async def delete_smtp_config(
    config_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an SMTP configuration."""
    config = db.query(SMTPConfig).filter(
        SMTPConfig.id == config_id,
        SMTPConfig.owner_id == current_user.id
    ).first()
    
    if not config:
        raise HTTPException(404, "Config not found")
    
    db.delete(config)
    db.commit()
    
    return {"message": "Config deleted"}


# ============== WebSocket ==============

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = None
):
    """WebSocket for real-time updates."""
    # Authenticate
    if not token:
        await websocket.close(code=4001)
        return
    
    token_data = decode_token(token)
    if not token_data or not token_data.user_id:
        await websocket.close(code=4001)
        return
    
    await manager.connect(websocket, token_data.user_id)
    
    try:
        while True:
            # Keep connection alive, handle any incoming messages
            data = await websocket.receive_text()
            # Could handle commands here if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket, token_data.user_id)


# ============== Utility Endpoints ==============

@app.get("/regions")
async def get_regions():
    """Get available AWS regions."""
    return AWSRelayService.get_available_regions()


@app.get("/health")
async def health_check():
    """API health check."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# ============== Admin Endpoints ==============

@app.get("/admin/users", response_model=List[UserResponse])
async def admin_list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all users (admin only)."""
    if not current_user.is_admin:
        raise HTTPException(403, "Admin access required")
    
    return db.query(User).all()


@app.get("/admin/instances")
async def admin_list_all_instances(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all instances across all users (admin only)."""
    if not current_user.is_admin:
        raise HTTPException(403, "Admin access required")
    
    instances = db.query(RelayInstance).filter(
        RelayInstance.status.notin_([InstanceStatus.TERMINATED])
    ).all()
    
    return [{
        "id": i.id,
        "owner_id": i.owner_id,
        "instance_id": i.instance_id,
        "public_ip": i.public_ip,
        "region": i.region,
        "status": i.status.value,
        "created_at": i.created_at.isoformat()
    } for i in instances]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
