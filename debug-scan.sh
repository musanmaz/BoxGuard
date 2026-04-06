#!/bin/bash

echo "🔍 BoxGuard debug script"
echo "========================"

echo ""
echo "📦 Package list check:"
echo "---------------------------"

echo "Checking packages on the Vagrant box..."
vagrant ssh -c "dpkg -l | grep -E '(openssl|sudo|nginx|java|policykit)' | head -10"

echo ""
echo "🌐 OSV API test:"
echo "----------------"

curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"openssl","ecosystem":"DEB"},"version":"1.1.0g-2ubuntu4"}' | jq '.vulns | length' 2>/dev/null || echo "jq not installed; raw response:"
curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"openssl","ecosystem":"DEB"},"version":"1.1.0g-2ubuntu4"}' | head -5

echo ""
echo "📡 Ubuntu USN feed test:"
echo "------------------------"

curl -s "https://ubuntu.com/security/notices/rss.xml" | grep -c "CVE-" || echo "USN feed unreachable"

echo ""
echo "🚀 BoxGuard:"
echo "-----------------"
echo "Run BoxGuard with:"
echo "./boxguard scan --vagrant-path ."
