#!/bin/bash
#
# Samba Setup Automation Script for Cybersecurity Competition
# For Rocky Linux 8 / RHEL-based distributions
#

# Exit on any error
set -e

# Text colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Log functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root"
    exit 1
fi

# Configuration Variables - MODIFY THESE AS NEEDED
SAMBA_SHARE_PATH="/srv/samba/secure"
WORKGROUP="WORKGROUP"
SERVER_NAME="TEAM12-SMB"
SAMBA_GROUP="sambausers"

# ============================================================================
# REPLACE THIS SECTION WITH ACTUAL USERS FROM THE SCORING SCRIPT
# Format: Array of usernames
# ============================================================================
SAMBA_USERS=("user1" "user2" "user3")
# ============================================================================

# ============================================================================
# REPLACE THIS SECTION WITH ACTUAL FILES FROM THE SCORING SCRIPT
# Format: Array of objects with name, content (optional), and size (optional)
# ============================================================================
declare -A FILE1=( [name]="testfile1.txt" [content]="This is test file 1" )
declare -A FILE2=( [name]="testfile2.txt" [content]="This is test file 2" )
declare -A FILE3=( [name]="largefile.txt" [size]="1048576" ) # 1MB file

FILES=(FILE1 FILE2 FILE3)
# ============================================================================

# Function to check if package is installed
is_installed() {
    if rpm -q "$1" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to create a file with specific content or size
create_file() {
    local file_path="$1"
    local content="$2"
    local size="$3"
    
    if [ -n "$content" ]; then
        echo "$content" > "$file_path"
        log_info "Created file $file_path with specific content"
    elif [ -n "$size" ]; then
        dd if=/dev/zero of="$file_path" bs=1 count=0 seek="$size" &>/dev/null
        log_info "Created file $file_path with size $size bytes"
    else
        log_warn "No content or size specified for $file_path"
        touch "$file_path"
    fi
}

# Step 1: Install Samba and dependencies
log_info "Step 1: Installing Samba and dependencies..."
dnf update -y
for pkg in samba samba-common samba-client policycoreutils-python-utils iptables-services; do
    if ! is_installed "$pkg"; then
        dnf install -y "$pkg"
        log_info "Installed $pkg"
    else
        log_info "$pkg already installed"
    fi
done

# Step 2: Configure firewall
log_info "Step 2: Configuring firewall..."
if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-service=samba
    firewall-cmd --permanent --add-port=445/tcp
    firewall-cmd --reload
    log_info "Firewall configured using firewalld"
else
    log_info "Creating iptables rules..."
    
    # Create iptables rules file
    cat > /etc/iptables-samba.rules << EOF
# Secure iptables configuration for SSH and Samba
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow established and related connections
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback interface
-A INPUT -i lo -j ACCEPT

# Allow SSH with rate limiting
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow Samba (SMB)
-A INPUT -p tcp --dport 445 -j ACCEPT

# Block invalid packets
-A INPUT -m conntrack --ctstate INVALID -j DROP

# Log and drop other traffic
-A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
-A INPUT -j DROP
COMMIT
EOF

    # Apply iptables rules
    iptables-restore < /etc/iptables-samba.rules
    service iptables save
    systemctl enable iptables
    log_info "Firewall configured using iptables"
fi

# Step 3: Create directory structure
log_info "Step 3: Creating directory structure..."
mkdir -p "$SAMBA_SHARE_PATH"
chmod 0770 "$SAMBA_SHARE_PATH"

# Step 4: Configure SELinux
log_info "Step 4: Configuring SELinux..."
semanage fcontext -a -t samba_share_t "${SAMBA_SHARE_PATH}(/.*)?"
restorecon -Rv "$SAMBA_SHARE_PATH"
setsebool -P samba_enable_home_dirs on
setsebool -P samba_export_all_ro=on samba_export_all_rw=on
log_info "SELinux configured for Samba"

# Step 5: Create group and manage users
log_info "Step 5: Managing users and groups..."

# Create Samba group if it doesn't exist
if ! getent group "$SAMBA_GROUP" >/dev/null; then
    groupadd "$SAMBA_GROUP"
    log_info "Created group $SAMBA_GROUP"
else
    log_info "Group $SAMBA_GROUP already exists"
fi

# Process users
for username in "${SAMBA_USERS[@]}"; do
    # Check if user exists
    if id "$username" &>/dev/null; then
        log_info "User $username already exists"
    else
        useradd -m "$username"
        # Set a default password - CHANGE THIS IN PRODUCTION!
        echo "${username}:Password123" | chpasswd
        log_info "Created user $username with default password"
    fi
    
    # Add user to Samba group
    if groups "$username" | grep -q "$SAMBA_GROUP"; then
        log_info "User $username is already in group $SAMBA_GROUP"
    else
        usermod -aG "$SAMBA_GROUP" "$username"
        log_info "Added user $username to group $SAMBA_GROUP"
    fi
    
    # Add user to Samba password database if not already there
    if ! pdbedit -L | grep -q "^$username:"; then
        (echo "Password123"; echo "Password123") | smbpasswd -a "$username"
        log_info "Added user $username to Samba password database"
    else
        log_info "User $username already in Samba password database"
    fi
done

# Step 6: Create Samba configuration
log_info "Step 6: Creating Samba configuration..."
cp /etc/samba/smb.conf /etc/samba/smb.conf.bak.$(date +%Y%m%d%H%M%S)

cat > /etc/samba/smb.conf << EOF
[global]
    workgroup = $WORKGROUP
    server string = Team 12 Samba Server
    netbios name = $SERVER_NAME
    server role = standalone server
    log file = /var/log/samba/log.%m
    max log size = 50
    logging = file
    
    # Security settings
    security = user
    passdb backend = tdbsam
    encrypt passwords = yes
    server min protocol = SMB2
    client min protocol = SMB2
    smb encrypt = required
    server signing = required
    
    # Network access controls
    hosts allow = 127.0.0.1 192.168.12.0/24 172.18.0.0/16
    hosts deny = 0.0.0.0/0
    
    # Disable guest access
    map to guest = never
    restrict anonymous = 2
    
    # Disable unnecessary services
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes

[SecureShare]
    comment = Secure Competition Share
    path = $SAMBA_SHARE_PATH
    browseable = yes
    read only = no
    guest ok = no
    valid users = @$SAMBA_GROUP
    create mask = 0660
    directory mask = 0770
    force create mode = 0660
    force directory mode = 0770
EOF

# Test configuration
testparm -s

# Step 7: Set ownership of share directory
log_info "Step 7: Setting ownership of share directory..."
chown -R root:"$SAMBA_GROUP" "$SAMBA_SHARE_PATH"

# Step 8: Create required files
log_info "Step 8: Creating required files..."
for file_ref in "${FILES[@]}"; do
    # Using indirect reference to access the associative array
    name="${!file_ref[name]}"
    content="${!file_ref[content]}"
    size="${!file_ref[size]}"
    
    create_file "$SAMBA_SHARE_PATH/$name" "$content" "$size"
    chown root:"$SAMBA_GROUP" "$SAMBA_SHARE_PATH/$name"
    chmod 0660 "$SAMBA_SHARE_PATH/$name"
done

# Step 9: Enable and start Samba services
log_info "Step 9: Starting Samba services..."
systemctl enable smb nmb
systemctl restart smb nmb

# Verify services are running
if systemctl is-active --quiet smb && systemctl is-active --quiet nmb; then
    log_info "Samba services started successfully!"
else
    log_error "Failed to start Samba services. Check logs with: systemctl status smb nmb"
    exit 1
fi

# Final verification
log_info "Testing Samba configuration..."
smbclient -L localhost -U user1%Password123!

log_info "==================================================="
log_info "Samba setup complete! Your configuration is ready."
log_info "Share name: SecureShare"
log_info "Share path: $SAMBA_SHARE_PATH"
log_info "Users configured: ${SAMBA_USERS[*]}"
log_info "Files created: $(for f in "${FILES[@]}"; do echo -n "${!f[name]} "; done)"
log_info "==================================================="
log_info "To test, run: smbclient //localhost/SecureShare -U user1"
log_info "Default password for new users: Password123"
log_info "IMPORTANT: Change these passwords in production!"

exit 0
