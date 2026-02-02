"""
AWS Relay Service
=================
Manages multiple EC2 relay instances with async operations.
Designed for multi-user, multi-instance scenarios.
"""

import boto3
import asyncio
import aiohttp
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor
import requests

logger = logging.getLogger(__name__)

# Thread pool for boto3 (not async-native)
executor = ThreadPoolExecutor(max_workers=10)


@dataclass
class InstanceInfo:
    """Data class for instance information."""
    instance_id: str
    public_ip: Optional[str]
    region: str
    state: str
    launch_time: Optional[datetime] = None


class AWSRelayService:
    """
    Service for managing AWS EC2 relay instances.
    Supports multiple concurrent instances across regions.
    """
    
    INSTANCE_TYPE = "t3.micro"
    SECURITY_GROUP_NAME = "relay-platform-sg"
    API_PORT = 8000
    
    # User data script for EC2 bootstrap
    USER_DATA_SCRIPT = '''#!/bin/bash
set -e
exec > >(tee /var/log/user-data.log) 2>&1

echo "=== Relay Agent Setup Started at $(date) ==="

# Update and install dependencies
dnf update -y
dnf install -y python3.11 python3.11-pip

# Create app directory
mkdir -p /opt/relay-agent
cd /opt/relay-agent

# Install Python packages
python3.11 -m pip install fastapi uvicorn[standard]

# Create the FastAPI application
cat > /opt/relay-agent/main.py << 'PYCODE'
import smtplib
import ssl
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Relay Agent")

class EmailPayload(BaseModel):
    smtp_user: str
    smtp_pass: str
    to_address: str
    subject: str
    body: str
    html_body: Optional[str] = None
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "hostname": socket.gethostname(),
        "timestamp": __import__("datetime").datetime.utcnow().isoformat()
    }

@app.post("/send")
async def send_email(payload: EmailPayload):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = payload.subject
        msg["From"] = payload.smtp_user
        msg["To"] = payload.to_address
        
        msg.attach(MIMEText(payload.body, "plain"))
        if payload.html_body:
            msg.attach(MIMEText(payload.html_body, "html"))
        
        context = ssl.create_default_context()
        with smtplib.SMTP(payload.smtp_host, payload.smtp_port) as server:
            server.starttls(context=context)
            server.login(payload.smtp_user, payload.smtp_pass)
            server.sendmail(payload.smtp_user, payload.to_address, msg.as_string())
        
        return {"success": True, "message": f"Sent to {payload.to_address}"}
    except smtplib.SMTPAuthenticationError as e:
        raise HTTPException(401, f"Auth failed: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/")
async def root():
    return {"service": "Relay Agent", "status": "running"}
PYCODE

# Create systemd service
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

systemctl daemon-reload
systemctl enable relay-agent
systemctl start relay-agent

echo "=== Relay Agent Setup Complete at $(date) ==="
'''

    def __init__(self, region: str = "us-east-1"):
        """Initialize the service for a specific region."""
        self.region = region
        self.session = boto3.Session(region_name=region)
        self.ec2 = self.session.client('ec2')
        self.ssm = self.session.client('ssm')
    
    @staticmethod
    def get_available_regions() -> List[str]:
        """Get list of available AWS regions."""
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1',
            'ap-south-1', 'ap-southeast-1', 'ap-southeast-2',
            'ap-northeast-1', 'ap-northeast-2', 'sa-east-1'
        ]
    
    def get_my_ip(self) -> str:
        """Get current public IP."""
        services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com'
        ]
        for svc in services:
            try:
                r = requests.get(svc, timeout=5)
                if r.status_code == 200:
                    return r.text.strip()
            except:
                continue
        raise RuntimeError("Could not determine public IP")
    
    def _get_latest_ami(self) -> str:
        """Get latest Amazon Linux 2023 AMI ID."""
        try:
            response = self.ssm.get_parameter(
                Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64'
            )
            return response['Parameter']['Value']
        except ClientError:
            # Fallback search
            response = self.ec2.describe_images(
                Owners=['amazon'],
                Filters=[
                    {'Name': 'name', 'Values': ['al2023-ami-2023*-x86_64']},
                    {'Name': 'state', 'Values': ['available']},
                ],
            )
            if not response['Images']:
                raise RuntimeError(f"No AMI found in {self.region}")
            images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
            return images[0]['ImageId']
    
    def _ensure_security_group(self, allowed_ip: str) -> str:
        """Create or update security group."""
        cidr = f"{allowed_ip}/32"
        
        try:
            response = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [self.SECURITY_GROUP_NAME]}]
            )
            if response['SecurityGroups']:
                sg_id = response['SecurityGroups'][0]['GroupId']
                self._update_sg_rules(sg_id, cidr)
                return sg_id
        except ClientError:
            pass
        
        # Create new SG
        vpcs = self.ec2.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])
        if not vpcs['Vpcs']:
            raise RuntimeError("No default VPC found")
        
        response = self.ec2.create_security_group(
            GroupName=self.SECURITY_GROUP_NAME,
            Description="Relay Platform Security Group",
            VpcId=vpcs['Vpcs'][0]['VpcId']
        )
        sg_id = response['GroupId']
        
        self.ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': self.API_PORT,
                    'ToPort': self.API_PORT,
                    'IpRanges': [{'CidrIp': cidr}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': cidr}]
                }
            ]
        )
        return sg_id
    
    def _update_sg_rules(self, sg_id: str, new_cidr: str):
        """Update security group with new IP."""
        try:
            sg = self.ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
            for perm in sg.get('IpPermissions', []):
                if perm.get('FromPort') in [self.API_PORT, 22]:
                    try:
                        self.ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[perm])
                    except:
                        pass
            
            self.ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {'IpProtocol': 'tcp', 'FromPort': self.API_PORT, 'ToPort': self.API_PORT,
                     'IpRanges': [{'CidrIp': new_cidr}]},
                    {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                     'IpRanges': [{'CidrIp': new_cidr}]}
                ]
            )
        except ClientError as e:
            logger.warning(f"Could not update SG rules: {e}")
    
    def launch_instance(self, name: Optional[str] = None) -> InstanceInfo:
        """
        Launch a new relay instance.
        This is a synchronous operation - call from thread pool for async.
        """
        logger.info(f"Launching instance in {self.region}")
        
        my_ip = self.get_my_ip()
        ami_id = self._get_latest_ami()
        sg_id = self._ensure_security_group(my_ip)
        
        tags = [
            {'Key': 'Name', 'Value': name or f'Relay-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}'},
            {'Key': 'Platform', 'Value': 'RelayPlatform'},
            {'Key': 'AutoTerminate', 'Value': 'true'}
        ]
        
        response = self.ec2.run_instances(
            ImageId=ami_id,
            InstanceType=self.INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[sg_id],
            UserData=self.USER_DATA_SCRIPT,
            TagSpecifications=[{'ResourceType': 'instance', 'Tags': tags}],
            InstanceInitiatedShutdownBehavior='terminate'
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        logger.info(f"Instance {instance_id} launched, waiting for running state...")
        
        # Wait for running
        waiter = self.ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        # Get public IP
        info = self.ec2.describe_instances(InstanceIds=[instance_id])
        instance_data = info['Reservations'][0]['Instances'][0]
        
        return InstanceInfo(
            instance_id=instance_id,
            public_ip=instance_data.get('PublicIpAddress'),
            region=self.region,
            state=instance_data['State']['Name'],
            launch_time=instance_data.get('LaunchTime')
        )
    
    def terminate_instance(self, instance_id: str) -> bool:
        """Terminate an instance."""
        try:
            self.ec2.terminate_instances(InstanceIds=[instance_id])
            logger.info(f"Terminated instance {instance_id}")
            return True
        except ClientError as e:
            logger.error(f"Failed to terminate {instance_id}: {e}")
            return False
    
    def get_instance_status(self, instance_id: str) -> Optional[InstanceInfo]:
        """Get current status of an instance."""
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            if not response['Reservations']:
                return None
            
            instance = response['Reservations'][0]['Instances'][0]
            return InstanceInfo(
                instance_id=instance_id,
                public_ip=instance.get('PublicIpAddress'),
                region=self.region,
                state=instance['State']['Name'],
                launch_time=instance.get('LaunchTime')
            )
        except ClientError:
            return None
    
    def list_platform_instances(self) -> List[InstanceInfo]:
        """List all instances tagged with our platform."""
        try:
            response = self.ec2.describe_instances(
                Filters=[
                    {'Name': 'tag:Platform', 'Values': ['RelayPlatform']},
                    {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping']}
                ]
            )
            
            instances = []
            for reservation in response['Reservations']:
                for inst in reservation['Instances']:
                    instances.append(InstanceInfo(
                        instance_id=inst['InstanceId'],
                        public_ip=inst.get('PublicIpAddress'),
                        region=self.region,
                        state=inst['State']['Name'],
                        launch_time=inst.get('LaunchTime')
                    ))
            return instances
        except ClientError as e:
            logger.error(f"Error listing instances: {e}")
            return []


class RelayAgentClient:
    """Async client for communicating with relay agents."""
    
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = aiohttp.ClientTimeout(total=timeout)
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if agent is healthy."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.base_url}/health") as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return {"status": "error", "code": resp.status}
        except asyncio.TimeoutError:
            return {"status": "timeout"}
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}
    
    async def send_email(
        self,
        smtp_user: str,
        smtp_pass: str,
        to_address: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None
    ) -> Dict[str, Any]:
        """Send an email through the relay."""
        payload = {
            "smtp_user": smtp_user,
            "smtp_pass": smtp_pass,
            "to_address": to_address,
            "subject": subject,
            "body": body
        }
        if html_body:
            payload["html_body"] = html_body
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(f"{self.base_url}/send", json=payload) as resp:
                    return await resp.json()
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def wait_until_ready(self, timeout: int = 180, interval: int = 10) -> bool:
        """Wait for the agent to become ready."""
        import time
        start = time.time()
        
        while (time.time() - start) < timeout:
            result = await self.health_check()
            if result.get("status") == "healthy":
                return True
            await asyncio.sleep(interval)
        
        return False


# Async wrapper functions for use with FastAPI
async def async_launch_instance(region: str, name: Optional[str] = None) -> InstanceInfo:
    """Launch instance asynchronously using thread pool."""
    loop = asyncio.get_event_loop()
    service = AWSRelayService(region)
    return await loop.run_in_executor(executor, service.launch_instance, name)


async def async_terminate_instance(region: str, instance_id: str) -> bool:
    """Terminate instance asynchronously."""
    loop = asyncio.get_event_loop()
    service = AWSRelayService(region)
    return await loop.run_in_executor(executor, service.terminate_instance, instance_id)


async def async_get_instance_status(region: str, instance_id: str) -> Optional[InstanceInfo]:
    """Get instance status asynchronously."""
    loop = asyncio.get_event_loop()
    service = AWSRelayService(region)
    return await loop.run_in_executor(executor, service.get_instance_status, instance_id)
