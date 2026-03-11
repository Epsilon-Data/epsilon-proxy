# AWS RDS / Aurora

Your database is an AWS RDS or Aurora instance inside a VPC.
RDS instances are typically not publicly accessible, so epsilon-proxy
must run inside the same VPC.

## Architecture

```
Your AWS Account
┌─────────────────────────────────────────────┐
│  VPC (e.g., 10.0.0.0/16)                   │
│                                             │
│  ┌─────────────┐      ┌──────────────────┐  │
│  │ RDS instance │◄────│ EC2 (t3.micro)   │  │
│  │ (private     │ 5432│ epsilon-proxy     │──┼── outbound TCP 7000 → Epsilon
│  │  subnet)     │     │ (private or       │  │
│  └─────────────┘      │  public subnet)   │  │
│                       └──────────────────┘  │
└─────────────────────────────────────────────┘
```

## Step 1: Launch an EC2 Instance

Launch a small EC2 in the same VPC as your RDS:

- **AMI:** Amazon Linux 2023 or Ubuntu 22.04
- **Instance type:** t3.micro (sufficient — proxy is lightweight)
- **Subnet:** Same VPC as RDS. Can be public or private subnet.
  - Public subnet: needs an internet gateway (for rathole tunnel outbound)
  - Private subnet: needs a NAT gateway (for rathole tunnel outbound)
- **Security group:** Allow outbound TCP 7000 + 443. No inbound rules needed.

## Step 2: Allow EC2 to Reach RDS

Edit the RDS security group to allow inbound PostgreSQL from the EC2:

```
Type:        PostgreSQL
Protocol:    TCP
Port:        5432
Source:      sg-xxxx (EC2's security group)
```

Or by private IP:
```
Source:      10.0.1.0/24 (EC2's subnet CIDR)
```

## Step 3: Install and Register

SSH into the EC2:

```bash
ssh ec2-user@<ec2-public-ip>

# Install
curl -fsSL https://get.epsilon-data.org/install.sh | sh

# Register — you will be prompted for your RDS endpoint, username,
# and password interactively. Password input is hidden.
# Credentials are stored locally on this EC2 only.
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub

# Start as systemd service
sudo tee /etc/systemd/system/epsilon-proxy.service > /dev/null <<EOF
[Unit]
Description=Epsilon Secure Proxy
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/epsilon-proxy start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now epsilon-proxy
```

## Step 4: Verify

```bash
# Check status
epsilon-proxy status

# Check health
curl http://localhost:8443/health
```

## Using IAM Authentication (Optional)

If your RDS uses IAM database authentication instead of passwords,
set the connection URL via environment variable:

```bash
# Generate temporary auth token
DB_TOKEN=$(aws rds generate-db-auth-token \
  --hostname mydb.xxxx.us-east-1.rds.amazonaws.com \
  --port 5432 \
  --username iam_user \
  --region us-east-1)

# Pass via env var (not CLI flag — keeps it out of shell history)
EPSILON_DB_URL="postgres://iam_user:${DB_TOKEN}@mydb.xxxx.us-east-1.rds.amazonaws.com:5432/mydb?sslmode=require" \
  epsilon-proxy register \
    --token ept_your_token_here \
    --api-url https://app.epsilon-data.org/api/v1/hub
```

Note: IAM tokens expire after 15 minutes. For IAM auth, the proxy would need
to refresh the token periodically. This is a planned feature.

## Cost

A `t3.micro` instance costs ~$7.50/month. The proxy uses minimal CPU and memory.
It only wakes up when a query is dispatched by the Epsilon coordinator.

## RDS Publicly Accessible (Not Recommended)

If you enable "Publicly Accessible" on your RDS and whitelist your proxy's IP,
you can run the proxy anywhere (no EC2 needed). However, this exposes your
RDS endpoint to the internet, which is against AWS security best practices.

```bash
# From any machine — credentials entered interactively
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub
```

## Network Requirements

| Direction | Port | Destination | Purpose |
|-----------|------|-------------|---------|
| EC2 → RDS | TCP 5432 | RDS endpoint | Database queries |
| EC2 → Internet | TCP 7000 | relay.epsilon-data.org | rathole tunnel |
| EC2 → Internet | TCP 443 | app.epsilon-data.org | API (registration, heartbeat) |

No inbound ports need to be opened on the EC2.
