#!/bin/bash

echo "🔍 CVE test script — Ubuntu 18.04 LTS"
echo "======================================"

# CVEs exercised by the test image
declare -A cves=(
    ["CVE-2021-3711"]="OpenSSL 1.1.0g - SM2 decryption vulnerability"
    ["CVE-2021-3156"]="sudo 1.8.21p2 - Heap-based buffer overflow"
    ["CVE-2021-4034"]="polkit - Local privilege escalation"
    ["CVE-2021-44228"]="Log4j - Remote code execution"
    ["CVE-2021-23017"]="nginx 1.14.0 - Multiple vulnerabilities"
    ["CVE-2021-33574"]="libc6 - Multiple vulnerabilities"
)

echo ""
echo "📦 Package versions:"
echo "----------------------"

openssl_version=$(openssl version 2>/dev/null | awk '{print $2}')
if [[ "$openssl_version" == "1.1.0g" ]]; then
    echo "✅ OpenSSL: $openssl_version (VULNERABLE — CVE-2021-3711)"
else
    echo "❌ OpenSSL: $openssl_version (not the vulnerable test version)"
fi

sudo_version=$(sudo --version 2>/dev/null | head -1 | awk '{print $3}')
if [[ "$sudo_version" == "1.8.21p2" ]]; then
    echo "✅ sudo: $sudo_version (VULNERABLE — CVE-2021-3156)"
else
    echo "❌ sudo: $sudo_version (not the vulnerable test version)"
fi

polkit_version=$(pkexec --version 2>/dev/null | awk '{print $2}')
if [[ "$polkit_version" == "0.105" ]]; then
    echo "✅ polkit: $polkit_version (VULNERABLE — CVE-2021-4034)"
else
    echo "❌ polkit: $polkit_version (not the vulnerable test version)"
fi

java_version=$(java -version 2>&1 | head -1 | awk -F'"' '{print $2}')
if [[ "$java_version" == "1.8.0_312" ]]; then
    echo "✅ Java: $java_version (VULNERABLE — CVE-2021-44228)"
else
    echo "❌ Java: $java_version (not the vulnerable test version)"
fi

nginx_version=$(nginx -v 2>&1 | awk '{print $3}' | sed 's/nginx\///')
if [[ "$nginx_version" == "1.14.0" ]]; then
    echo "✅ nginx: $nginx_version (VULNERABLE — CVE-2021-23017)"
else
    echo "❌ nginx: $nginx_version (not the vulnerable test version)"
fi

libc_version=$(ldd --version 2>/dev/null | head -1 | awk '{print $NF}')
if [[ "$libc_version" == "2.27" ]]; then
    echo "✅ libc: $libc_version (VULNERABLE — CVE-2021-33574)"
else
    echo "❌ libc: $libc_version (not the vulnerable test version)"
fi

echo ""
echo "🚀 BoxGuard command:"
echo "------------------------"
echo "./boxguard scan --vagrant-path ."
echo ""
echo "📊 Expected findings (illustrative):"
echo "--------------------"
echo "• OpenSSL CVE-2021-3711 (HIGH)"
echo "• sudo CVE-2021-3156 (HIGH)"
echo "• polkit CVE-2021-4034 (CRITICAL)"
echo "• Java Log4j CVE-2021-44228 (CRITICAL)"
echo "• nginx CVE-2021-23017 (MEDIUM)"
echo "• libc CVE-2021-33574 (MEDIUM)"
echo ""
echo "✨ Test script finished."
