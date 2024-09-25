#!/bin/bash

#This Script audits your Nginx server configuration against CIS Security Benchmark 2.1.0 released 06-28-2024. 

#Use Bash shell with sudo rights to execute.

#This script is to be used if Nginx is running on - Ubuntu OS

#CIS Benchmark Details: https://downloads.cisecurity.org/#/

#x.x.x - shows the section number along with the benchmark check


echo -ne "\n########## Running the NGINX CIS Checker ##########"

#Check admin rights for script execution

checkid() {
echo -e "\n\n(Checking admin execution rights)"
if [[ "${UID}" -ne 0 ]]
then
	echo -e "\e[31mFAILURE\e[0m\nPlease use sudo for script execution"
	exit 1
else
	echo -ne "\e[38;5;42mSUCCESS\e[39m"
fi
}
checkid

#Check if OS is Ubuntu based
echo -e "\n\n(Checking if OS is Ubuntu)"
checkos() {
OS=$(cat /etc/*release | grep -w NAME | cut -d = -f2 | tr -d '""')
if [[ (! "${OS}" == 'Ubuntu') && (! "${OS}" == 'ubuntu') && (! "${OS}" == 'UBUNTU') ]]
then
	echo -e "\e[31mFAILURE\e[0m\nThe base OS for this Nginx image is not Ubuntu. Please use appropriate script"
	exit 1
else
	echo -e "\e[38;5;42mSUCCESS\e[39m"
fi
}
checkos

echo -e "\n##### Evaluating the NGINX Server against CIS Benchmarks ######"
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
percent=$((pass*100/total))
echo -e "\n\e[1mCIS Compliance Checks Passed: $pass/$total\e[0m"
echo -e "\e[1mCIS Compliance Percentage: $percent%\e[0m"
}

#1.1.1- Ensure NGINX is installed (Automated)
echo -e "\n\e[4mCIS 1.1.1\e[0m - Ensure NGINX is installed (Automated)"
nginx -v 
if  [[ "${?}" -ne 0 ]]
then
	echo -e "\e[31mFAILURE\e[0m\nNginx is not installed on this server"
	failed
	exit 1
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nNginx is installed"
	passed
fi

#1.1.2 Ensure NGINX is installed from source (Manual)

#1.2.1 Ensure package manager repositories are properly configured (Manual)

#1.2.2 Ensure the latest software package is installed (Manual)

#2.1.1 Ensure only required modules are installed (Manual)

#2.1.2 Ensure HTTP WebDAV module is not installed (Automated)
echo -e "\n\e[4mCIS 2.1.2\e[0m - Ensure HTTP WebDAV module is not installed (Automated)"
nginx -V 2>&1 | grep http_dav_module > /dev/null
if  [[ "${?}" -ne 0 ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nhttp_dav_module is not installed on this server"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nhttp_dav_module is installed on this server"
        failed
	echo -e "Remediation: NGINX does not support the removal of modules using the dnf method of installation. In order to remove modules from NGINX, you will need to compile NGINX from source. References: 1. http://nginx.org/en/docs/configure.html 2. https://tools.ietf.org/html/rfc4918"
fi

#2.1.3 Ensure modules with gzip functionality are disabled (Automated)
echo -e "\n\e[4mCIS 2.1.3\e[0m - Ensure modules with gzip functionality are disabled (Automated)"
nginx -V 2>&1 | grep -E '(http_gzip_module|http_gzip_static_module)' > /dev/null
if  [[ "${?}" -ne 0 ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nGZIP is not installed on this server"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nGZIP is installed on this server"
        failed
        echo -e "Remediation: In order to disable the http_gzip_module and the http_gzip_static_module, NGINX must be recompiled from source. This can be accomplished using the below command in the folder you used during your original compilation. This must be done without the --withhttp_gzip_static_module or --with-http_gzip_module configuration directives. ./configure --without-http_gzip_module --without-http_gzip_static_module. Default Value: The http_gzip_module is enabled by default in the source build, and the http_gzip_static_module is not. Only the http_gzip_static_module is enabled by default in the dnf package. References: 1. http://nginx.org/en/docs/configure.html 2. http://nginx.org/en/docs/configure.html 3. http://nginx.org/en/docs/http/ngx_http_gzip_module.html 4. http://nginx.org/en/docs/http/ngx_http_gzip_static_module.html"
fi


#2.1.4 Ensure the autoindex module is disabled (Automated)
echo -e "\n\e[4mCIS 2.1.4\e[0m - Ensure the autoindex module is disabled (Automated)"
a=$(egrep -i '^\s*autoindex\s+' /etc/nginx/nginx.conf)
b=$(egrep -i '^\s*autoindex\s+' /etc/nginx/conf.d/*)
if  [[ ( "$a" == 'autoindex on' ) || ( "$b" == 'autoindex on' ) ]]
then
        echo -e "\e[31mFAILURE\e[0m\nautoindex is not disabled on this server"
        failed
        echo -e "Remediation: Search the NGINX configuration files (nginx.conf and any included configuration files) to find autoindex directives. Set the value for all autoindex directives to off, or remove those directives. References: 1. http://nginx.org/en/docs/http/ngx_http_autoindex_module.html"
else
        echo -e "\e[38;5;42mSUCCESS\e[39m\nautoindex is disabled on this server"
        passed
fi

#2.2.1 Ensure that NGINX is run using a non-privileged, dedicated service account (Automated)
echo -e "\n\e[4mCIS 2.2.1\e[0m - Ensure that NGINX is run using a non-privileged, dedicated service account (Automated)"
user=$(grep -Pi -- '^\h*user\h+[^;\n\r]+\h*;.*$' /etc/nginx/nginx.conf | cut -d ' ' -f 2 | cut -d ';' -f 1)
a=$(sudo -l -U $user)
if  [[ "$a" =~ 'not allowed' ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nnginx service $user is running with non-sudo user privilege on this server"
        passed
else
	echo -e "\e[31mFAILURE\e[0m\nginx service $user is running with sudo user privilege on this server"
	failed
	echo -e "Remediation: Add a system account for the $user user with a home directory of /var/cache/nginx and a shell of /sbin/nologin so it does not have the ability to log in, then add the nginx user to be used by nginx: useradd nginx -r -g nginx -d /var/cache/nginx -s /sbin/nologin Then add the nginx user to /etc/nginx/nginx.conf by adding the user directive as shown below: user nginx; Default Value: By default, if nginx is compiled from source, the user and group are nobody. If downloaded from dnf, the user and group nginx and the account are not privileged."
fi

b=$(groups $user | cut -d ':' -f 1)
c=$(groups $user | cut -d ':' -f 2 | cut -d ' ' -f 2)
if [[ ( "$b" == "$c ") ]]
then
	echo -e "\e[38;5;42mSUCCESS\e[39m\nnginx service $user is not part of any other groups than the primary user group $b"
	passed
else
	echo -e "\e[31mFAILURE\e[0m\nnginx service $user is part of other groups than the primary user group $b: $c"
	failed
	echo -e "Remediation: Add a system account for the nginx $user with a home directory of /var/cache/nginx and a shell of /sbin/nologin so it does not have the ability to log in, then add the nginx user to be used by nginx: useradd nginx -r -g nginx -d /var/cache/nginx -s /sbin/nologin Then add the nginx user to /etc/nginx/nginx.conf by adding the user directive as shown below: user nginx; Default Value:By default, if nginx is compiled from source, the user and group are nobody. If downloaded from dnf, the user and group nginx and the account are not privileged."
fi

#2.2.2 Ensure the NGINX service account is locked (Automated)
echo -e "\n\e[4mCIS 2.2.2\e[0m - Ensure the NGINX service account is locked (Automated)"
a=$(passwd -S "$(awk '$1~/^\s*user\s*$/ {print $2}' /etc/nginx/nginx.conf | sed -r 's/;.*//g')")
b=$(awk '$1~/^\s*user\s*$/ {print $2}' /etc/nginx/nginx.conf | sed -r 's/;.*//g')
echo "$a"
if  [[ "$a" =~ 'L' ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX service account $b is locked"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nNGINX service account is not locked"
        failed
	echo -e "Remediation: Use the passwd command to lock the nginx service account: passwd -l $b)"
fi

#2.2.3 Ensure the NGINX service account has an invalid shell (Automated)
echo -e "\n\e[4mCIS 2.2.3\e[0m - Ensure the NGINX service account has an invalid shell (Automated)"
shell()
{
	l_output="" l_output2="" l_out=""
	if [ -f /etc/nginx/nginx.conf ]; then
	l_user="$(awk '$1~/^\s*user\s*$/ {print $2}' /etc/nginx/nginx.conf |
	sed -r 's/;.*//g')"
	l_valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
	l_out="$(awk -v pat="$l_valid_shells" -v ngusr="$l_user" -F: '($(NF) ~pat && $1==ngusr) { $(NF-1) }' /etc/passwd)"
	if [ -z "$l_out" ]; then
	l_output=" - NGINX user account: \"$l_user\" has an invalid shell"
	else
	l_output2=" - NGINX user account: \"$l_user\" has a valid shell:\"$l_out\""
	fi
	else
	l_output2=" - NGINX user account can not be determined.\n - file:\"/etc/nginx/nginx.conf\" is missing"
	fi
	if [ -z "$l_output2" ]; then
	echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX service account $l_user has an invalid shell"
	passed
	else
	echo -e "\e[31mFAILURE\e[0m\n - Reason(s) for auditfailure:\n$l_output2\n"
	echo -e "Remediation: Remediation: Change the login shell for the nginx account to /sbin/nologin by using the following command: usermod -s /sbin/nologin $l_user"
	fi
}
shell

#2.3.1 Ensure NGINX directories and files are owned by root (Automated)
echo -e "\n\e[4mCIS 2.3.1\e[0m - Ensure NGINX directories and files are owned by root (Automated)"
a=$(stat /etc/nginx | grep -i -m 1 access)
if  [[ "$a" =~ 'root' ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX directories and files are owned by root"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nNGINX directories and files are not owned by root"
        failed
        echo -e "Remediation: Run the following command to ensure ownership and group ownership is set to root: chown -R root:root /etc/nginx)"
fi

#2.3.2 Ensure access to NGINX directories and files is restricted (Automated)
echo -e "\n\e[4mCIS 2.3.2\e[0m - Ensure access to NGINX directories and files is restricted (Automated)"
dir=$(find /etc/nginx -type d -exec stat -Lc "%n %a" {} + | cut -d " " -f 2)
fil=$(find /etc/nginx -type f -exec stat -Lc "%n %a" {} + | cut -d " " -f 2)
for d in dir
do
	if [[ "$d" > 755  ]]
	then
	echo -e "\e[31mFAILURE\e[0m\nSome permissions of NGINX sub-directories under directory /etc/nginx are over permissive"
	failed
	echo -e "Remediation: Run the following command to set 755 permissions on all NGINX sub-directories under /etc/nginx: find /etc/nginx -type d -exec chmod go-w {} +"
	else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nAll NGINX sub-directories under /etc/nginx have strict permissions"
	passed
	fi
done

for f in fil
do
        if [[ "$f" > 644  ]]
        then
        echo -e "\e[31mFAILURE\e[0m\nSome file permissions of files under NGINX directory /etc/nginx are over permissive"
        failed
        echo -e "Remediation: Run the following command to set 755 permissions on all NGINX directories: find /etc/nginx -type f -exec chmod ug-x,o-rwx {} +"
        else
        echo -e "\e[38;5;42mSUCCESS\e[39m\nAll files under NGINX directory /etc/nginx  have strict permissions"
        passed
        fi
done

#2.3.3 Ensure the NGINX process ID (PID) file is secured (Automated)
echo -e "\n\e[4mCIS 2.3.3\e[0m - Ensure the NGINX process ID (PID) file is secured (Automated)"
a=$(stat -L -c "%U:%G" /var/run/nginx.pid)
b=$(stat -L -c "%a" /var/run/nginx.pid)
if  [[ "$a" =~ 'root' ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX process PID file is owned by root"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nNGINX process PID file is not owned by root"
        failed
        echo -e "Remediation: If the PID file is not owned by root, issue this command: chown root:root /var/run/nginx.pid"
fi

if  [[ "$b" > 644 ]]
then
        echo -e "\e[31mFAILURE\e[0m\nNGINX process PID file is over permissive"
        failed
	echo -e "Remediation: If the PID file has permissions greater than 644, issue this command: chmod u-x,go-wx /var/run/nginx.pid"
else
        echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX process PID file is restricted"
        passed
fi

#2.3.4 Ensure the core dump directory is secured (Manual)

#2.4.1 Ensure NGINX only listens for network connections on authorized ports (Manual)

#2.4.2 Ensure requests for unknown host names are rejected (Automated)
echo -e "\n\e[4mCIS 2.4.2\e[0m - Ensure requests for unknown host names are rejected (Automated)"
curl -k -v https://127.0.0.1 -H 'Host: invalid.host.com'

#2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0 (Automated)
echo -e "\n\e[4mCIS 2.4.3\e[0m - Ensure keepalive_timeout is 10 seconds or less, but not 0 (Automated)"
grep -ir keepalive_timeout /etc/nginx

#2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0 (Automated)
echo -e "\n\e[4mCIS 2.4.4\e[0m - Ensure send_timeout is set to 10 seconds or less, but not 0 (Automated)"
grep -ir send_timeout /etc/nginx

#2.5.1 Ensure server_tokens directive is set to `off` (Automated)
echo -e "\n\e[4mCIS 2.5.1\e[0m - Ensure server_tokens directive is set to `off` (Automated)"
curl -I 127.0.0.1 | grep -i server

#2.5.2 Ensure default error and index.html pages do not reference NGINX (Automated)
echo -e "\n\e[4mCIS 2.5.2\e[0m - Ensure default error and index.html pages do not reference NGINX (Automated)"
grep -i nginx /usr/share/nginx/html/index.html
grep -i nginx /usr/share/nginx/html/50x.html

#2.5.3 Ensure hidden file serving is disabled (Manual)

#2.5.4 Ensure the NGINX reverse proxy does not enable information disclosure (Automated)
echo -e "\n\e[4mCIS 2.5.4\e[0m - Ensure the NGINX reverse proxy does not enable information disclosure (Automated)"
grep proxy_hide_header /etc/nginx/nginx.conf

#3.1 Ensure detailed logging is enabled (Manual)

#3.2 Ensure access logging is enabled (Manual)

#3.3 Ensure error logging is enabled and set to the info logging level (Automated)
echo -e "\n\e[4mCIS 3.3\e[0m - Ensure error logging is enabled and set to the info logging level (Automated)"
grep error_log /etc/nginx/nginx.conf

#3.4 Ensure log files are rotated (Automated)
echo -e "\n\e[4mCIS 3.4\e[0m - Ensure log files are rotated (Automated)"
cat /etc/logrotate.d/nginx | grep weekly
cat /etc/logrotate.d/nginx | grep rotate

#3.5 Ensure error logs are sent to a remote syslog server (Manual)

#3.6 Ensure access logs are sent to a remote syslog server (Manual)

#3.7 Ensure proxies pass source IP information (Manual)

#4.1.1 Ensure HTTP is redirected to HTTPS (Manual)

#4.1.2 Ensure a trusted certificate and trust chain is installed (Manual)

#4.1.3 Ensure private key permissions are restricted (Automated)
echo -e "\n\e[4mCIS 4.1.3\e[0m - Ensure private key permissions are restricted (Automated)"
find /etc/nginx/ -name '*.key' -exec stat -Lc "%n %a" {} +

#4.1.4 Ensure only modern TLS protocols are used (Automated)
echo -e "\n\e[4mCIS 4.1.4\e[0m - Ensure only modern TLS protocols are used (Automated)"
grep -ir ssl_protocol /etc/nginx

#4.1.5 Disable weak ciphers (Manual)

#4.1.6 Ensure custom Diffie-Hellman parameters are used (Automated)
echo -e "\n\e[4mCIS 4.1.6\e[0m - Ensure custom Diffie-Hellman parameters are used (Automated)"
grep ssl_dhparam /etc/nginx/nginx.conf

#4.1.7 Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Automated)
echo -e "\n\e[4mCIS 4.1.7\e[0m - Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Automated)"
grep -ir ssl_stapling /etc/nginx

#4.1.8 Ensure HTTP Strict Transport Security (HSTS) is enabled (Automated)
echo -e "\n\e[4mCIS 4.1.8\e[0m - Ensure HTTP Strict Transport Security (HSTS) is enabled (Automated)"
grep -ir Strict-Transport-Security /etc/nginx

#4.1.9 Ensure upstream server traffic is authenticated with a client certificate (Automated)
echo -e "\n\e[4mCIS 4.1.9\e[0m - Ensure upstream server traffic is authenticated with a client certificate (Automated)"
grep -ir proxy_ssl_certificate /etc/nginx

#4.1.10 Ensure the upstream traffic server certificate is trusted (Manual)

#4.1.11 Ensure your domain is preloaded (Manual)

#4.1.12 Ensure session resumption is disabled to enable perfect forward security (Automated)
echo -e "\n\e[4mCIS 4.1.12\e[0m - Ensure session resumption is disabled to enable perfect forward security (Automated)"
grep -ir ssl_session_tickets /etc/nginx

#4.1.13 Ensure HTTP/2.0 is used (Automated)
echo -e "\n\e[4mCIS 4.1.12\e[0m - Ensure session resumption is disabled to enable perfect forward security (Automated)"
grep -ir http2 /etc/nginx

#4.1.14 Ensure only Perfect Forward Secrecy Ciphers are Leveraged (Manual)
echo -e "\n\e[4mCIS 4.1.14\e[0m - Ensure only Perfect Forward Secrecy Ciphers are Leveraged (Manual)"
grep -ir ssl_ciphers /etc/nginx/
grep -ir proxy_ssl_ciphers /etc/nginx

#5.1.1 Ensure allow and deny filters limit access to specific IP addresses (Manual)

#5.1.2 Ensure only approved HTTP methods are allowed (Manual)

#5.2.1 Ensure timeout values for reading the client header and body are set correctly (Automated)
echo -e "\n\e[4mCIS - 5.2.1\e[0m Ensure timeout values for reading the client header and body are set correctly (Automated)"
grep -ir timeout /etc/nginx

#5.2.2 Ensure the maximum request body size is set correctly (Automated)
echo -e "\n\e[4mCIS 5.2.2\e[0m - Ensure the maximum request body size is set correctly (Automated)"
grep -ir client_max_body_size /etc/nginx

#5.2.3 Ensure the maximum buffer size for URIs is defined (Automated)
echo -e "\n\e[4mCIS 5.2.3\e[0m - Ensure the maximum buffer size for URIs is defined (Automated)"
grep -ir large_client_header_buffers /etc/nginx/

#5.2.4 Ensure the number of connections per IP address is limited (Manual)

#5.2.5 Ensure rate limits by IP address are set (Manual)

#5.3.1 Ensure X-Frame-Options header is configured and enabled (Automated)
echo -e "\n\e[4mCIS 5.3.1\e[0m - Ensure X-Frame-Options header is configured and enabled (Automated)"
grep -ir X-Frame-Options /etc/nginx

#5.3.2 Ensure X-Content-Type-Options header is configured and enabled (Automated)
echo -e "\n\e[4mCIS 5.3.2\e[0m - Ensure X-Content-Type-Options header is configured and enabled (Automated)"
grep -ir X-Content-Type-Options /etc/nginx

#5.3.3 Ensure that Content Security Policy (CSP) is enabled and configured properly (Manual)

#5.3.4 Ensure the Referrer Policy is enabled and configured properly (Manual)

score
