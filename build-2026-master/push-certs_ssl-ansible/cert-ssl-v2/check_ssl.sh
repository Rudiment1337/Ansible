#!/bin/bash
#set -x
# ENV
PATH_SCRIPT_UP_DATA_NETBOX="push-certs_ssl-ansible/cert-ssl-v2/python_script/dynam_inv.py"

# # #

python3 "PATH_SCRIPT_UP_DATA_NETBOX" > "/tmp/.update_host.json"
cat "/tmp/.update_host.json" | grep "site_url" > "/tmp/.raw_host.txt"
RAW_DATE=$(cat "/tmp/.update_host.json" | grep "ssl_cert_expected_not_after" | awk 'NR==1 {gsub(/[",]/, "", $2); print $2; exit}')
ACT_DATE=$(LC_TIME=C date -d "$RAW_DATE" +"%b %e")

# # #

echo ACTUAL DATE: $ACT_DATE
rm -f "/tmp/.host.txt"
declare -A seen
while IFS= read -r line; do
                url=$(echo "$line" | sed -E 's/.*"site_url":\s*"([^"]+)".*/\1/')
		host="${url#https://}"
		host="${host%/}"
		if [[ "$host" == *:* ]]; then
		        result="$host"
		else
 		        result="${host}:443"
		fi
		if [[ -z "${seen[$result]}" ]]; then
	        	seen[$result]=1
			echo "$result" >> "/tmp/.host.txt"
		fi
done < "/tmp/.raw_host.txt"
while IFS= read -r line; do
		if [ $(ping -c 1 $(echo "$line" | sed 's/:.*//') 2>&1 | grep -Ec "100% packet loss|Name or service not known") -ge 1 ]; then
			echo "Host FAIL - $line"
		else
			if [ "$(openssl s_client -connect $line -servername $(echo $line | sed 's/:.*//') </dev/null 2>/dev/null | openssl x509 -noout -dates | grep -c "$ACT_DATE")" -gt 0 ]; then echo "1 - $line"; else echo "0 - $line"; fi
		fi
done < "/tmp/.host.txt"
