#!/bin/bash
echo "=== Samba Security Audit ==="
CONFIG="/etc/samba/smb.conf"

# Check protocol version
if grep -i "server min protocol" $CONFIG | grep -i -E "NT1|LANMAN|SMB1|SMB2"; then
  echo "❌ CRITICAL: Outdated SMB protocol in use. Recommend SMB3_11"
else
  echo "✅ Using secure SMB protocol version"
fi

# Check encryption settings
if ! grep -i "server smb encrypt" $CONFIG | grep -i -E "required|mandatory"; then
  echo "❌ CRITICAL: SMB encryption not required"
else
  echo "✅ SMB encryption properly configured"
fi

# Check signing settings
if ! grep -i "server signing" $CONFIG | grep -i -E "required|mandatory"; then
  echo "❌ HIGH: SMB signing not required"
else
  echo "✅ SMB signing properly configured"
fi

# Check guest access
if grep -i "map to guest" $CONFIG | grep -i -E "Bad User"; then
  echo "✅ Guest access properly restricted"
else
  echo "❌ HIGH: Guest access misconfigured"
fi

# Check for anonymous access
if ! grep -i "restrict anonymous" $CONFIG | grep -i -E "1|2"; then
  echo "❌ MEDIUM: Anonymous access not fully restricted"
else
  echo "✅ Anonymous access restricted"
fi

# Check for plaintext passwords
if grep -i "encrypt passwords" $CONFIG | grep -i "no"; then
  echo "❌ CRITICAL: Plaintext passwords allowed"
else
  echo "✅ Password encryption enabled"
fi

# Check for hosts restrictions
if ! grep -i "hosts allow" $CONFIG; then
  echo "❌ HIGH: No IP restrictions configured"
else
  echo "✅ IP restrictions in place"
fi

# Check for guest-allowed shares
echo "\n=== Examining shares for guest access ==="
testparm -s | grep -A2 "\[" | grep -E "guest ok|public" | grep "yes"
if [ $? -eq 0 ]; then
  echo "❌ CRITICAL: Guest access allowed on some shares"
else
  echo "✅ No guest-accessible shares found"
fi

# Check for proper SELinux context
if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
  echo "\n=== SELinux Status ==="
  if ! ls -ldZ /srv/samba 2>/dev/null | grep -q samba_share_t; then
    echo "❌ MEDIUM: Samba directory may not have correct SELinux context"
  else
    echo "✅ SELinux contexts appear correct"
  fi
fi
