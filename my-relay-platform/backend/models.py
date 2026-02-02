"""
Database Models
===============
SQLAlchemy models for the relay platform.
Supports SQLite (dev) and PostgreSQL (production).
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, 
    ForeignKey, Text, Enum, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import enum

Base = declarative_base()


class InstanceStatus(enum.Enum):
    """Possible states for a relay instance."""
    PENDING = "pending"
    LAUNCHING = "launching"
    INITIALIZING = "initializing"
    READY = "ready"
    SENDING = "sending"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    ERROR = "error"


class EmailStatus(enum.Enum):
    """Possible states for an email."""
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"


class User(Base):
    """User account for team access."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    instances = relationship("RelayInstance", back_populates="owner")
    emails = relationship("EmailRecord", back_populates="sender")
    smtp_configs = relationship("SMTPConfig", back_populates="owner")


class SMTPConfig(Base):
    """Saved SMTP configurations for reuse."""
    __tablename__ = "smtp_configs"
    
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)  # e.g., "Marketing Gmail"
    smtp_user = Column(String(100), nullable=False)
    smtp_pass_encrypted = Column(String(500), nullable=False)  # Encrypted
    smtp_host = Column(String(100), default="smtp.gmail.com")
    smtp_port = Column(Integer, default=587)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    owner = relationship("User", back_populates="smtp_configs")


class RelayInstance(Base):
    """Represents an EC2 relay instance."""
    __tablename__ = "relay_instances"
    
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # AWS Details
    instance_id = Column(String(50), unique=True, nullable=True, index=True)
    public_ip = Column(String(50), nullable=True)
    region = Column(String(20), nullable=False)
    instance_type = Column(String(20), default="t3.micro")
    
    # Status tracking
    status = Column(Enum(InstanceStatus), default=InstanceStatus.PENDING)
    status_message = Column(String(500), nullable=True)
    
    # Metadata
    name = Column(String(100), nullable=True)  # Optional friendly name
    created_at = Column(DateTime, default=datetime.utcnow)
    ready_at = Column(DateTime, nullable=True)
    terminated_at = Column(DateTime, nullable=True)
    
    # Stats
    emails_sent = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)
    
    # Relationships
    owner = relationship("User", back_populates="instances")
    emails = relationship("EmailRecord", back_populates="instance")
    
    @property
    def api_url(self) -> Optional[str]:
        """Get the API URL for this instance."""
        if self.public_ip:
            return f"http://{self.public_ip}:8000"
        return None
    
    @property
    def is_active(self) -> bool:
        """Check if instance is in an active state."""
        return self.status in [
            InstanceStatus.LAUNCHING,
            InstanceStatus.INITIALIZING,
            InstanceStatus.READY,
            InstanceStatus.SENDING
        ]


class EmailRecord(Base):
    """Record of emails sent through the platform."""
    __tablename__ = "email_records"
    
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    instance_id = Column(Integer, ForeignKey("relay_instances.id"), nullable=True)
    
    # Email details
    from_address = Column(String(100), nullable=False)
    to_address = Column(String(100), nullable=False)
    subject = Column(String(500), nullable=False)
    body_preview = Column(String(500), nullable=True)  # First 500 chars
    
    # Status
    status = Column(Enum(EmailStatus), default=EmailStatus.QUEUED)
    error_message = Column(Text, nullable=True)
    
    # Metadata
    relay_ip = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    sent_at = Column(DateTime, nullable=True)
    
    # Relationships
    sender = relationship("User", back_populates="emails")
    instance = relationship("RelayInstance", back_populates="emails")


class AuditLog(Base):
    """Audit log for important actions."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(50), nullable=False)  # e.g., "instance_launch", "email_sent"
    resource_type = Column(String(50), nullable=True)  # e.g., "instance", "email"
    resource_id = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)  # JSON string with extra details
    ip_address = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# Database setup helpers
def get_database_url(use_postgres: bool = False) -> str:
    """Get the database URL based on environment."""
    if use_postgres:
        import os
        return os.getenv(
            "DATABASE_URL",
            "postgresql://user:pass@localhost:5432/relay_platform"
        )
    return "sqlite:///./relay_platform.db"


def init_database(database_url: str = None):
    """Initialize the database and create tables."""
    if database_url is None:
        database_url = get_database_url()
    
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if "sqlite" in database_url else {}
    )
    Base.metadata.create_all(bind=engine)
    return engine


def get_session_factory(engine):
    """Create a session factory."""
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)
