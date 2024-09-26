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
        echo -e "\e[38;5;42mSUCCESS\e[39m\nModule http_dav_module is not installed on this server"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nModule http_dav_module is installed on this server"
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
        echo -e "\e[31mFAILURE\e[0m\nAutoindex is not disabled on this server"
        failed
        echo -e "Remediation: Search the NGINX configuration files (nginx.conf and any included configuration files) to find autoindex directives. Set the value for all autoindex directives to off, or remove those directives. References: 1. http://nginx.org/en/docs/http/ngx_http_autoindex_module.html"
else
        echo -e "\e[38;5;42mSUCCESS\e[39m\nAutoindex is disabled on this server"
        passed
fi

#2.2.1 Ensure that NGINX is run using a non-privileged, dedicated service account (Automated)
echo -e "\n\e[4mCIS 2.2.1\e[0m - Ensure that NGINX is run using a non-privileged, dedicated service account (Automated)"
user=$(grep -Pi -- '^\h*user\h+[^;\n\r]+\h*;.*$' /etc/nginx/nginx.conf | cut -d ' ' -f 2 | cut -d ';' -f 1)
a=$(sudo -l -U $user)
if  [[ "$a" =~ 'not allowed' ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX service $user is running with non-sudo user privilege on this server\n"
        passed
else
	echo -e "\e[31mFAILURE\e[0m\nNGINX service $user is running with sudo user privilege on this server"
	failed
	echo -e "Remediation: Add a system account for the $user user with a home directory of /var/cache/nginx and a shell of /sbin/nologin so it does not have the ability to log in, then add the nginx user to be used by nginx: useradd nginx -r -g nginx -d /var/cache/nginx -s /sbin/nologin Then add the nginx user to /etc/nginx/nginx.conf by adding the user directive as shown below: user nginx; Default Value: By default, if nginx is compiled from source, the user and group are nobody. If downloaded from dnf, the user and group nginx and the account are not privileged\n"
fi

b=$(groups $user | cut -d ':' -f 1)
c=$(groups $user | cut -d ':' -f 2 | cut -d ' ' -f 2)
if [[ ( "$b" == "$c" ) ]]
then
	echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX service $user is not part of any other groups than the primary user group $b"
	passed
else
	echo -e "\e[31mFAILURE\e[0m\nNGINX service $user is part of other groups than the primary user group $b: $c"
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
	failed
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
		echo -e "Remediation: Run the following command to set 755 permissions on all NGINX sub-directories under /etc/nginx: find /etc/nginx -type d -exec chmod go-w {} +\n"
	else
		echo -e "\e[38;5;42mSUCCESS\e[39m\nAll NGINX sub-directories under /etc/nginx have strict permissions\n"
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
        echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX process PID file is owned by root\n"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nNGINX process PID file is not owned by root"
        failed
        echo -e "Remediation: If the PID file is not owned by root, issue this command: chown root:root /var/run/nginx.pid\n"
fi

if  [[ "$b" > 644 ]]
then
        echo -e "\e[31mFAILURE\e[0m\nNGINX process PID file is over permissive"
        failed
	echo -e "Remediation: If the PID file has permissions greater than 644, issue this command: chmod u-x,go-wx /var/run/nginx.pid\n"
else
        echo -e "\e[38;5;42mSUCCESS\e[39m\nNGINX process PID file is restricted\n"
        passed
fi

#2.3.4 Ensure the core dump directory is secured (Manual)

#2.4.1 Ensure NGINX only listens for network connections on authorized ports (Manual)

#2.4.2 Ensure requests for unknown host names are rejected (Automated)
echo -e "\n\e[4mCIS 2.4.2\e[0m - Ensure requests for unknown host names are rejected (Automated)"
curl -k -v https://127.0.0.1 -H 'Host: invalid.host.com'
if  [[ "${?}" -ne 0 ]]
then
        echo -e "\e[31mFAILURE\e[0m\nRequests for unknown host names are not rejected"
        failed
        echo -e "Remediation: Remediation: Ensure your first server block mirrors the below in your nginx configuration, either at /etc/nginx/nginx.conf or any included file within your nginx config: server { return 404;} Then investigate each server block to ensure the server_name directive is explicitly defined. Each server block should look similar to the below with the defined hostname of the associated server block in the server_name directive. For example, if your server is cisecurity.org, the configuration should look like the below example: server { listen 443;server_name cisecurity.org;.....}"
else
        echo -e "\e[38;5;42mSUCCESS\e[39m\nRequests for unknown host names are not rejected"
        passed
fi

#2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0 (Automated)
echo -e "\n\e[4mCIS 2.4.3\e[0m - Ensure keepalive_timeout is 10 seconds or less, but not 0 (Automated)"
a=$(grep -ir keepalive_timeout /etc/nginx | cut -d " " -f 2 | cut -d ";" -f 1)
if [[ (( "$a" < 10 ) || ( "$a" == 10 )) && ( "$a" != '' ) ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nThe directive keepalive_timeout is $a"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nThe directive keepalive_timeout is : $a which is not 10 seconds or less"
        failed
	echo -e "Remediation: Find the HTTP or server block of your nginx configuration, and add the keepalive_timeout directive. Set it to 10 seconds or less, but not 0. This example command sets it to 10 seconds: keepalive_timeout 10;"
fi

#2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0 (Automated)
echo -e "\n\e[4mCIS 2.4.4\e[0m - Ensure send_timeout is set to 10 seconds or less, but not 0 (Automated)"
a=$(grep -ir send_timeout /etc/nginx | cut -d " " -f 2 | cut -d ";" -f 1)
if [[ (( "$a" < 10 ) || ( "$a" == 10 )) && ( "$a" != '' ) ]]
then
        echo -e "\e[38;5;42mSUCCESS\e[39m\nThe send_timeout directive is set to $a"
        passed
else
        echo -e "\e[31mFAILURE\e[0m\nThe send_timeout directive is : $a which is not 10 seconds or less"
        failed
	echo -e "Remediation: Find the HTTP or server block of your nginx configuration, and add the send_timeout directive. Set it to 10 seconds or less, but not 0. send_timeout 10;"
fi

#2.5.1 Ensure server_tokens directive is set to `off` (Automated)
echo -e "\n\e[4mCIS 2.5.1\e[0m - Ensure server_tokens directive is set to off (Automated)"
a=$(curl -I 127.0.0.1 | grep -i server | cut -d " " -f 2)
echo "$a"
if  [[ "$a" =~ 'nginx' ]]
then
	echo -e "\e[31mFAILURE\e[0m\nThe server_tokens directive is set to on. Nginx version is visible"
	failed
	echo -e "Remediation: To disable the server_tokens directive, set it to off inside of every server block in your nginx.conf or in the http block:server {...server_tokens off;...}"
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nThe server_tokens directive is set to off in all server blocks"
	passed
fi

#2.5.2 Ensure default error and index.html pages do not reference NGINX (Automated)
echo -e "\n\e[4mCIS 2.5.2\e[0m - Ensure default error and index.html pages do not reference NGINX (Automated)"
a=$(grep -i nginx /usr/share/nginx/html/index.html)
b=$(grep -i nginx /usr/share/nginx/html/50x.html)
if  [[ ( "$a" =~ 'nginx' ) || ( "$b" =~ 'nginx' ) ]]
then
        echo -e "\e[31mFAILURE\e[0m\nDefault error or index.html page references NGINX"
	failed
	echo -e "Remediation: Edit /usr/share/nginx/html/index.html and usr/share/nginx/html/50x.html and remove any lines that reference NGINX."
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nDefault error and index.html pages do not reference NGINX " 
	passed
fi

#2.5.3 Ensure hidden file serving is disabled (Manual)

#2.5.4 Ensure the NGINX reverse proxy does not enable information disclosure (Automated)
echo -e "\n\e[4mCIS 2.5.4\e[0m - Ensure the NGINX reverse proxy does not enable information disclosure (Automated)"
a=$(grep proxy_hide_header /etc/nginx/nginx.conf)
if  [[ !( "$a" =~ 'proxy_hide_header X-Powered-By' ) || !( "$a" =~ 'proxy_hide_header Server' ) ]]
then
	echo -e "\e[31mFAILURE\e[0m\nProxy_hide_headers: <X-Powered-By> and/or <Server> not enabled"
	failed
	echo -e "Remediation: Implement the below directives as part of your location block. Edit /etc/nginx/nginx.conf and add the following: location /docs { .... proxy_hide_header X-Powered-By; proxy_hide_header Server;....}"
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nProxy_hide_headers: <X-Powered-By> and <Server> are enabled"
	passed
fi

#3.1 Ensure detailed logging is enabled (Manual)

#3.2 Ensure access logging is enabled (Manual)

#3.3 Ensure error logging is enabled and set to the info logging level (Automated)
echo -e "\n\e[4mCIS 3.3\e[0m - Ensure error logging is enabled and set to the info logging level (Automated)"
a=$(grep error_log /etc/nginx/nginx.conf)
if  [[ ! ( "$a" == '' ) && ! ( "$a" =~ '#' ) && ( "$a" =~ 'info' ) ]]
then
	echo -e "\e[38;5;42mSUCCESS\e[39m\nError logging is enabled and set to the info logging level"
	passed
else
	echo -e "\e[31mFAILURE\e[0m\nError logging is not enabled or set to info logging level"
	failed
	echo -e "Remediation: Edit /etc/nginx/nginx.conf so the error_log directive is present and not commented out. The error_log should be configured to the logging location of your choice. The configuration should look similar to the below: error_log /var/log/nginx/error_log.log info;"
fi

#3.4 Ensure log files are rotated (Automated)
echo -e "\n\e[4mCIS 3.4\e[0m - Ensure log files are rotated (Automated)"
cat /etc/logrotate.d/nginx | grep weekly
if  [[ "$?" -ne '0' ]]
then
	echo -e "\e[31mFAILURE\e[0m\nLog files are not being compressed on weekly basis"
	failed
	echo -e "Remediation: To change log compression from daily to weekly: sed -i <s/daily/weekly> /etc/logrotate.d/nginx\n"
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nLog files are being compressed on weekly basis\n"
	passed
fi

a=$(cat /etc/logrotate.d/nginx | grep -m 1 rotate | cut -d " " -f 2)
if  [[ "$a" -ne '13' ]]
then
	echo -e "\e[31mFAILURE\e[0m\nLog files are being rotated every $a weeks. Recommended rotation is every 13 weeks"
	failed
	echo -e	"Remediation: To change log rotation from every year to every 13 weeks: sed -i <s/rotate 52/rotate 13/> /etc/logrotate.d/nginx"
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nLog files are being rotated every 13 weeks"
	passed
fi

#3.5 Ensure error logs are sent to a remote syslog server (Manual)

#3.6 Ensure access logs are sent to a remote syslog server (Manual)

#3.7 Ensure proxies pass source IP information (Manual)

#4.1.1 Ensure HTTP is redirected to HTTPS (Manual)

#4.1.2 Ensure a trusted certificate and trust chain is installed (Manual)

#4.1.3 Ensure private key permissions are restricted (Automated)
echo -e "\n\e[4mCIS 4.1.3\e[0m - Ensure private key permissions are restricted (Automated)"
b=$(find /etc/nginx/ -name '*.key' -exec stat -Lc "%n %a" {} + | cut -d " " -f 2)
if [[ ( "$b" < '400' ) || ( "$b" == '400' ) ]]
then
	echo -e "\e[38;5;42mSUCCESS\e[39m\nPrivate key permissions are restricted"
	passed
else
	echo -e "\e[31mFAILURE\e[0m\nPrivate key permissions are over-permissive"
	failed
	echo -e "Remediation: Run the following command to remove excessive permissions on key files in the /etc/nginx/ directory. Note: The directory /etc/nginx/ should be replaced with the location of your key file. find /etc/nginx/ -name '*.key' -exec chmod u-wx,go-rwx {} +"
fi

#4.1.4 Ensure only modern TLS protocols are used (Automated)
echo -e "\n\e[4mCIS 4.1.4\e[0m - Ensure only modern TLS protocols are used (Automated)"
grep -ir ssl_protocol /etc/nginx | grep 'v1\s'
if [[ "$?" = '0' ]]
then
	echo -e "\e[31mFAILURE\e[0m\nTLS 1.0 is enabled"
	failed
	echo -e "Remediation: Run the following commands to change your ssl_protocols if they are already configured. This remediation advice assumes your nginx configuration file does not include server configuration outside of /etc/nginx/nginx.conf. You may have to also inspect the include files in your nginx.conf to ensure this is properly implemented. Web Server: sed -i <s/ssl_protocols[^;]*;/ssl_protocols TLSv1.2 TLSv1.3;/> /etc/nginx/nginx.conf Proxy: sed -i <s/proxy_ssl_protocols[^;]*;/proxy_ssl_protocols TLSv1.2 TLSv1.3;/> /etc/nginx/nginx.confIf your ssl_protocols are not already configured, this can be accomplished manually by opening your web server or proxy server configuration file and manually adding the directives. Web Server: server { ssl_protocols TLSv1.2 TLSv1.3; } Proxy: location / { proxy_pass cisecurity.org; proxy_ssl_protocols TLSv1.2 TLSv1.3; }\n"
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nTLS 1.0 is disabled\n"
	passed
fi

grep -ir ssl_protocol /etc/nginx | grep 'v1.1\s'
if [[ "$?" = '0' ]]
then
        echo -e "\e[31mFAILURE\e[0m\nTLS 1.1 is enabled"
        failed
        echo -e "Remediation: Run the following commands to change your ssl_protocols if they are already configured. This remediation advice assumes your nginx configuration file does not include server configuration outside of /etc/nginx/nginx.conf. You may have to also inspect the include files in your nginx.conf to ensure this is properly implemented. Web Server: sed -i <s/ssl_protocols[^;]*;/ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;/> /etc/nginx/nginx.conf Proxy: sed -i <s/proxy_ssl_protocols[^;]*;/proxy_ssl_protocols TLSv1.2 TLSv1.3;/> /etc/nginx/nginx.confIf your ssl_protocols are not already configured, this can be accomplished manually by opening your web server or proxy server configuration file and manually adding the directives. Web Server: server { ssl_protocols TLSv1.2 TLSv1.3; } Proxy: location / { proxy_pass cisecurity.org; proxy_ssl_protocols TLSv1.2 TLSv1.3; }"
else
	echo -e "\e[38;5;42mSUCCESS\e[39m\nTLS 1.1 is disabled"
	passed
fi

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
