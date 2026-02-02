# 📧 Relay Platform - Team Edition

A **multi-user, multi-instance** email relay management platform. Deploy as a web service for your entire team to manage disposable AWS EC2 email relays.

## 🎯 Key Features

| Feature | Description |
|---------|-------------|
| **Multi-User** | Team members can register and manage their own instances |
| **Multi-Instance** | Run multiple relay instances simultaneously |
| **Real-Time Updates** | WebSocket support for live status updates |
| **Email History** | Track all sent emails with status and relay IP |
| **Region Selection** | Launch instances in any AWS region |
| **JWT Auth** | Secure token-based authentication |
| **Admin Panel** | Admin users can view all instances |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TEAM USERS                                   │
│     👤 User A    👤 User B    👤 User C    👤 Admin                  │
└─────────────────────────┬───────────────────────────────────────────┘
                          │ HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      YOUR SERVER                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              React Frontend (Port 3000)                      │    │
│  │        Modern dashboard with real-time updates               │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                          │ API Calls                                 │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              FastAPI Backend (Port 8080)                     │    │
│  │   • JWT Authentication    • Background Tasks                 │    │
│  │   • WebSocket Updates     • SQLite/PostgreSQL                │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────────────┘
                          │ boto3
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS CLOUD                                    │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ Instance A   │  │ Instance B   │  │ Instance C   │              │
│  │ 54.x.x.1     │  │ 52.x.x.2     │  │ 18.x.x.3     │              │
│  │ us-east-1    │  │ eu-west-1    │  │ ap-south-1   │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

1. **Python 3.9+**
2. **Node.js 18+** (for frontend)
3. **AWS Account** with configured credentials

### 1. Setup Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS (if not already done)
aws configure

# Run the server
uvicorn main:app --reload --host 0.0.0.0 --port 8080
```

### 2. Setup Frontend

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

### 3. Access the Platform

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8080
- **API Docs**: http://localhost:8080/docs

### Default Login

```
Username: admin
Password: admin123
```

## 📁 Project Structure

```
relay_platform/
├── backend/
│   ├── main.py           # FastAPI application
│   ├── models.py         # Database models (SQLAlchemy)
│   ├── auth.py           # JWT authentication
│   ├── aws_service.py    # AWS EC2 management
│   └── requirements.txt  # Python dependencies
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx       # Main React component
│   │   └── main.jsx      # Entry point
│   ├── index.html        # HTML template
│   ├── package.json      # Node dependencies
│   └── vite.config.js    # Vite configuration
│
└── README.md             # This file
```

## 🔌 API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register new user |
| `/auth/login` | POST | Login, get JWT token |
| `/auth/me` | GET | Get current user info |

### Instances

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/instances` | GET | List user's instances |
| `/instances` | POST | Launch new instance |
| `/instances/{id}` | DELETE | Terminate instance |
| `/instances/{id}/health` | GET | Check agent health |

### Emails

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/emails/send` | POST | Send email via instance |
| `/emails` | GET | List sent emails |

### Utilities

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/regions` | GET | List AWS regions |
| `/health` | GET | API health check |
| `/ws` | WebSocket | Real-time updates |

## 🛠️ Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
# Security (CHANGE IN PRODUCTION!)
SECRET_KEY=your-super-secret-key-change-this

# Database (SQLite by default)
DATABASE_URL=sqlite:///./relay_platform.db

# For PostgreSQL:
# DATABASE_URL=postgresql://user:pass@localhost:5432/relay_platform

# AWS (or use aws configure)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1
```

### Production Deployment

For production, I recommend:

1. **Use PostgreSQL** instead of SQLite
2. **Use a reverse proxy** (nginx/Caddy) with HTTPS
3. **Set strong SECRET_KEY**
4. **Use Docker** for easy deployment

#### Docker Compose Example

```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/relay
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      - db

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"

  db:
    image: postgres:15
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: relay
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

## 👥 Team Usage

### User Roles

| Role | Permissions |
|------|-------------|
| **User** | Manage own instances, send emails |
| **Admin** | View all instances, manage users |

### Workflow

1. **Team Lead**: Sets up the platform on a server
2. **Team Members**: Register accounts
3. **Each Member**: 
   - Launch their own instances
   - Send emails through their instances
   - View their email history
4. **When Done**: Terminate instances to save costs

## 💰 Cost Management

### Per-Instance Cost

| Component | Cost |
|-----------|------|
| t3.micro | ~$0.0104/hour |
| Data transfer | ~$0.09/GB |

### Cost Saving Tips

1. **Terminate when done** - Don't leave instances running
2. **Use smaller regions** - Some regions are cheaper
3. **Batch emails** - Send multiple emails per instance before terminating

## 🔒 Security Best Practices

1. **Change default admin password** immediately
2. **Use HTTPS** in production
3. **Encrypt SMTP passwords** in database (add encryption to `smtp_pass_encrypted`)
4. **Restrict CORS** to your frontend domain
5. **Use VPN/Private network** for internal team use

## 🐛 Troubleshooting

### "Instance stuck in initializing"

The EC2 user-data script might be slow. Check:
1. AWS Console → EC2 → Instance → System Log
2. Wait up to 3 minutes for installation

### "WebSocket not connecting"

Make sure to pass the token as a query parameter:
```javascript
new WebSocket(`ws://localhost:8080/ws?token=${token}`)
```

### "CORS error"

Update `allow_origins` in `main.py` to include your frontend URL.

## 📊 Monitoring

### Database

```python
# Check active instances
SELECT * FROM relay_instances WHERE status != 'terminated';

# Email stats per user
SELECT sender_id, COUNT(*) as total, 
       SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent
FROM email_records GROUP BY sender_id;
```

### AWS

```bash
# List all platform instances
aws ec2 describe-instances \
  --filters "Name=tag:Platform,Values=RelayPlatform" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name,PublicIpAddress]'
```

## 🚧 Future Enhancements

- [ ] Email templates
- [ ] Scheduled sending
- [ ] Rate limiting per user
- [ ] Email analytics
- [ ] Bulk import recipients
- [ ] SMTP credential encryption
- [ ] Two-factor authentication
- [ ] Slack/Discord notifications

## 📄 License

MIT License - Use freely for your team!
