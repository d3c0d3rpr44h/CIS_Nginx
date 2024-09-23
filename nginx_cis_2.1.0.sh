#!/bin/bash

#This Script audits your Nginx server configuration against CIS Security Benchmark 2.1.0 released 06-28-2024. 

#Use Bash shell with sudo rights to execute.

#This script is to be used if Nginx is running on - Ubuntu OS

#CIS Benchmark Details: https://downloads.cisecurity.org/#/

#x.x.x - shows the section number along with the benchmark check


echo -ne "\n########## Running the NGINX CIS Checker ##########"

#Check admin rights for script execution

checkid() {
echo -e "\n\n##### Checking admin execution rights #####"
if [[ "${UID}" -ne 0 ]]
then
	echo -e "FAILURE\nPlease use sudo for script execution"
	exit 1
else
	echo -ne "SUCCESS"
fi
}
checkid

#Check if OS is Ubuntu based
echo -e "\n\n##### Checking if OS is Ubuntu #####"
checkos() {
OS=$(cat /etc/*release | grep -w NAME | cut -d = -f2 | tr -d '""')
if [[ (! "${OS}" == 'Ubuntu') && (! "${OS}" == 'ubuntu') && (! "${OS}" == 'UBUNTU') ]]
then
	echo -e "FAILURE\nThe base OS for this Nginx image is not Ubuntu. Please use appropriate script"
	exit 1
else
	echo -e "SUCCESS"
fi
}
checkos

echo -e "\n##### Analyzing the Server for CIS Benchmarks ######"
pass=0
fail=0

passed() {
((++pass))
}

failed() {
((++fail))
}

score(){
total=$((pass+fail))
echo -e "Your CIS Score for this server: $pass/$total"
}

#1.1.1- Ensure NGINX is installed (Automated)
echo -e "\nCIS 1.1.1 - Ensure NGINX is installed (Automated)"
nginx -v 
if  [[ "${?}" -ne 0 ]]
then
	echo -e "FAILURE\nNginx is not installed on this server"
	failed
	exit 1
else
	echo -e "SUCCESS\nNginx is installed"
	passed
fi

#1.1.2 Ensure NGINX is installed from source (Manual)

#1.2.1 Ensure package manager repositories are properly configured (Manual)

#1.2.2 Ensure the latest software package is installed (Manual)

#2.1.1 Ensure only required modules are installed (Manual)

#2.1.2 Ensure HTTP WebDAV module is not installed (Automated)
echo -e "\nCIS 2.1.2 - Ensure HTTP WebDAV module is not installed (Automated)"
nginx -V 2>&1 | grep http_dav_module > /dev/null
if  [[ "${?}" -ne 0 ]]
then
        echo -e "SUCCESS\nhttp_dav_module is not installed on this server"
        passed
else
        echo -e "FAILURE\nhttp_dav_module is installed on this server"
        failed
	echo -e "Remediation: NGINX does not support the removal of modules using the dnf method of installation. In order to remove modules from NGINX, you will need to compile NGINX from source. References: 1. http://nginx.org/en/docs/configure.html 2. https://tools.ietf.org/html/rfc4918"
fi

#2.1.3 Ensure modules with gzip functionality are disabled (Automated)
echo -e "\nCIS 2.1.3 - Ensure modules with gzip functionality are disabled (Automated)"
nginx -V 2>&1 | grep -E '(http_gzip_module|http_gzip_static_module)' > /dev/null
if  [[ "${?}" -ne 0 ]]
then
        echo -e "SUCCESS\n GZIP is not installed on this server"
        passed
else
        echo -e "FAILURE\nGZIP is installed on this server"
        failed
        echo -e "Remediation: In order to disable the http_gzip_module and the http_gzip_static_module, NGINX must be recompiled from source. This can be accomplished using the below command in the folder you used during your original compilation. This must be done without the --withhttp_gzip_static_module or --with-http_gzip_module configuration directives. ./configure --without-http_gzip_module --without-http_gzip_static_module. Default Value: The http_gzip_module is enabled by default in the source build, and the http_gzip_static_module is not. Only the http_gzip_static_module is enabled by default in the dnf package. References: 1. http://nginx.org/en/docs/configure.html 2. http://nginx.org/en/docs/configure.html 3. http://nginx.org/en/docs/http/ngx_http_gzip_module.html 4. http://nginx.org/en/docs/http/ngx_http_gzip_static_module.html"
fi


#2.1.4 Ensure the autoindex module is disabled (Automated)
echo -e "\nCIS 2.1.4 - Ensure the autoindex module is disabled (Automated)"
egrep -i '^\s*autoindex\s+' /etc/nginx/nginx.conf
egrep -i '^\s*autoindex\s+' /etc/nginx/conf.d/* 

#2.2.1 Ensure that NGINX is run using a non-privileged, dedicated service account (Automated)
echo -e "\nCIS 2.2.1 - Ensure that NGINX is run using a non-privileged, dedicated service account (Automated)"
grep -Pi -- '^\h*user\h+[^;\n\r]+\h*;.*$' /etc/nginx/nginx.conf
sudo -l -U nginx
groups nginx

#2.2.2 Ensure the NGINX service account is locked (Automated)
echo -e "\nCIS 2.2.2 - Ensure the NGINX service account is locked (Automated)"
passwd -S "$(awk '$1~/^\s*user\s*$/ {print $2}' /etc/nginx/nginx.conf | sed -r 's/;.*//g')"

#2.2.3 Ensure the NGINX service account has an invalid shell (Automated)
echo -e "\nCIS 2.2.3 - Ensure the NGINX service account has an invalid shell (Automated)"
shell()
{
 l_output="" l_output2="" l_out=""
 if [ -f /etc/nginx/nginx.conf ]; then
 l_user="$(awk '$1~/^\s*user\s*$/ {print $2}' /etc/nginx/nginx.conf |
sed -r 's/;.*//g')"
 l_valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste
-s -d '|' - ))$"
 l_out="$(awk -v pat="$l_valid_shells" -v ngusr="$l_user" -F: '($(NF) ~
pat && $1==ngusr) { $(NF-1) }' /etc/passwd)"
 if [ -z "$l_out" ]; then
 l_output=" - NGINX user account: \"$l_user\" has an invalid shell"
 else
 l_output2=" - NGINX user account: \"$l_user\" has a valid shell:
\"$l_out\""
 fi
 else
 l_output2=" - NGINX user account can not be determined.\n - file:
\"/etc/nginx/nginx.conf\" is missing"
 fi
 if [ -z "$l_output2" ]; then
 echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
 else
 echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit
failure:\n$l_output2\n"
 fi
}
shell

#2.3.1 Ensure NGINX directories and files are owned by root (Automated)
echo -e "\nCIS 2.3.1 - Ensure NGINX directories and files are owned by root (Automated)"
stat /etc/nginx

#2.3.2 Ensure access to NGINX directories and files is restricted (Automated)
echo -e "\nCIS 2.3.2 - Ensure access to NGINX directories and files is restricted (Automated)"
find /etc/nginx -type d -exec stat -Lc "%n %a" {} +
find /etc/nginx -type f -exec stat -Lc "%n %a" {} +

#2.3.3 Ensure the NGINX process ID (PID) file is secured (Automated)
echo -e "\nCIS 2.3.3 - Ensure the NGINX process ID (PID) file is secured (Automated)"
stat -L -c "%U:%G" /var/run/nginx.pid && stat -L -c "%a" /var/run/nginx.pid

#2.3.4 Ensure the core dump directory is secured (Manual)

#2.4.1 Ensure NGINX only listens for network connections on authorized ports (Manual)

#2.4.2 Ensure requests for unknown host names are rejected (Automated)
echo -e "\nCIS 2.4.2 - Ensure requests for unknown host names are rejected (Automated)"
curl -k -v https://127.0.0.1 -H 'Host: invalid.host.com'

#2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0 (Automated)
echo -e "\nCIS 2.4.3 - Ensure keepalive_timeout is 10 seconds or less, but not 0 (Automated)"
grep -ir keepalive_timeout /etc/nginx

#2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0 (Automated)
echo -e "\nCIS 2.4.4 - Ensure send_timeout is set to 10 seconds or less, but not 0 (Automated)"
grep -ir send_timeout /etc/nginx

#2.5.1 Ensure server_tokens directive is set to `off` (Automated)
echo -e "\nCIS 2.5.1 - Ensure server_tokens directive is set to `off` (Automated)"
curl -I 127.0.0.1 | grep -i server

#2.5.2 Ensure default error and index.html pages do not reference NGINX (Automated)
echo -e "\nCIS 2.5.2 - Ensure default error and index.html pages do not reference NGINX (Automated)"
grep -i nginx /usr/share/nginx/html/index.html
grep -i nginx /usr/share/nginx/html/50x.html

#2.5.3 Ensure hidden file serving is disabled (Manual)

#2.5.4 Ensure the NGINX reverse proxy does not enable information disclosure (Automated)
echo -e "\nCIS 2.5.4 - Ensure the NGINX reverse proxy does not enable information disclosure (Automated)"
grep proxy_hide_header /etc/nginx/nginx.conf

#3.1 Ensure detailed logging is enabled (Manual)

#3.2 Ensure access logging is enabled (Manual)

#3.3 Ensure error logging is enabled and set to the info logging level (Automated)
echo -e "\nCIS 3.3 - Ensure error logging is enabled and set to the info logging level (Automated)"
grep error_log /etc/nginx/nginx.conf

#3.4 Ensure log files are rotated (Automated)
echo -e "\nCIS 3.4 - Ensure log files are rotated (Automated)"
cat /etc/logrotate.d/nginx | grep weekly
cat /etc/logrotate.d/nginx | grep rotate

#3.5 Ensure error logs are sent to a remote syslog server (Manual)

#3.6 Ensure access logs are sent to a remote syslog server (Manual)

#3.7 Ensure proxies pass source IP information (Manual)

#4.1.1 Ensure HTTP is redirected to HTTPS (Manual)

#4.1.2 Ensure a trusted certificate and trust chain is installed (Manual)

#4.1.3 Ensure private key permissions are restricted (Automated)
echo -e "\nCIS 4.1.3 - Ensure private key permissions are restricted (Automated)"
find /etc/nginx/ -name '*.key' -exec stat -Lc "%n %a" {} +

#4.1.4 Ensure only modern TLS protocols are used (Automated)
echo -e "\nCIS 4.1.4 - Ensure only modern TLS protocols are used (Automated)"
grep -ir ssl_protocol /etc/nginx

#4.1.5 Disable weak ciphers (Manual)

#4.1.6 Ensure custom Diffie-Hellman parameters are used (Automated)
echo -e "\nCIS 4.1.6 - Ensure custom Diffie-Hellman parameters are used (Automated)"
grep ssl_dhparam /etc/nginx/nginx.conf

#4.1.7 Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Automated)
echo -e "\nCIS 4.1.7 - Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Automated)"
grep -ir ssl_stapling /etc/nginx

#4.1.8 Ensure HTTP Strict Transport Security (HSTS) is enabled (Automated)
echo -e "\nCIS 4.1.8 - Ensure HTTP Strict Transport Security (HSTS) is enabled (Automated)"
grep -ir Strict-Transport-Security /etc/nginx

#4.1.9 Ensure upstream server traffic is authenticated with a client certificate (Automated)
echo -e "\nCIS 4.1.9 - Ensure upstream server traffic is authenticated with a client certificate (Automated)"
grep -ir proxy_ssl_certificate /etc/nginx

#4.1.10 Ensure the upstream traffic server certificate is trusted (Manual)

#4.1.11 Ensure your domain is preloaded (Manual)

#4.1.12 Ensure session resumption is disabled to enable perfect forward security (Automated)
echo -e "\nCIS 4.1.12 - Ensure session resumption is disabled to enable perfect forward security (Automated)"
grep -ir ssl_session_tickets /etc/nginx

#4.1.13 Ensure HTTP/2.0 is used (Automated)
echo -e "\nCIS 4.1.12 - Ensure session resumption is disabled to enable perfect forward security (Automated)"
grep -ir http2 /etc/nginx

#4.1.14 Ensure only Perfect Forward Secrecy Ciphers are Leveraged (Manual)
echo -e "\nCIS 4.1.14 - Ensure only Perfect Forward Secrecy Ciphers are Leveraged (Manual)"
grep -ir ssl_ciphers /etc/nginx/
grep -ir proxy_ssl_ciphers /etc/nginx

#5.1.1 Ensure allow and deny filters limit access to specific IP addresses (Manual)

#5.1.2 Ensure only approved HTTP methods are allowed (Manual)

#5.2.1 Ensure timeout values for reading the client header and body are set correctly (Automated)
echo -e "\nCIS - 5.2.1 Ensure timeout values for reading the client header and body are set correctly (Automated)"
grep -ir timeout /etc/nginx

#5.2.2 Ensure the maximum request body size is set correctly (Automated)
echo -e "\nCIS 5.2.2 - Ensure the maximum request body size is set correctly (Automated)"
grep -ir client_max_body_size /etc/nginx

#5.2.3 Ensure the maximum buffer size for URIs is defined (Automated)
echo -e "\nCIS 5.2.3 - Ensure the maximum buffer size for URIs is defined (Automated)"
grep -ir large_client_header_buffers /etc/nginx/

#5.2.4 Ensure the number of connections per IP address is limited (Manual)

#5.2.5 Ensure rate limits by IP address are set (Manual)

#5.3.1 Ensure X-Frame-Options header is configured and enabled (Automated)
echo -e "\nCIS 5.3.1 - Ensure X-Frame-Options header is configured and enabled (Automated)"
grep -ir X-Frame-Options /etc/nginx

#5.3.2 Ensure X-Content-Type-Options header is configured and enabled (Automated)
echo -e "\nCIS 5.3.2 - Ensure X-Content-Type-Options header is configured and enabled (Automated)"
grep -ir X-Content-Type-Options /etc/nginx

#5.3.3 Ensure that Content Security Policy (CSP) is enabled and configured properly (Manual)

#5.3.4 Ensure the Referrer Policy is enabled and configured properly (Manual)

score
