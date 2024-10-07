#bin/bash
echo -ne "\n######## Updating package Repository ########\n"
sudo apt update

echo -ne "\n######## Installing Nginx ########\n"
sudo apt install nginx -y
sudo apt auto-remove

echo -ne "\nTry opening Ubuntu_IP:80. \nYou should see default Nginx Welcome Page\n"

echo -ne "\n######## Configuring your custom Nginx App -NginxApp ########\n"
sudo mkdir /var/www/NginxApp
cat > /var/www/NginxApp/index.html <<EOF
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Welcome to Nginx App Made by You for You</title>
</head>
<body>
    <h1>Hello, Nginx!</h1>
    <p>Time to test</p>
</body>
</html>
EOF
#sudo echo "<!doctype html>
#<html>
#<head>
#    <meta charset="utf-8">
#    <title>Welcome to Nginx App Made by You for You</title>
#</head>
#<body>
#    <h1>Hello, Nginx!</h1>
#    <p>Time to test</p>
#/body>
#/html>" > /var/www/NginxApp/index.html

cat > /etc/nginx/sites-enabled/NginxApp <<EOF
server {
       listen 81;
       listen [::]:81;

       server_name example.ubuntu.com;

       root /var/www/NginxApp;
       index index.html;

       location / {
               try_files $uri $uri/ =404;
       }
}
EOF
#sudo echo 'server {
#       listen 81;
#      listen [::]:81;
#       server_name example.ubuntu.com;
#       root /var/www/NginxApp;
#       index index.html;
#       location / {
#              try_files $uri $uri/ =404;
#      }
#      }' >  /etc/nginx/sites-enabled/NginxApp
sudo systemctl restart nginx
echo -ne "\nInitial Setup completed. \nTry accessing Ubuntu_IP:81. \nYou should see Nginx page. \nEnjoy!!"
