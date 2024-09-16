#bin/bash
echo "\n####### Updating package Repository ########\n"
sudo apt update

echo "\n######## Installing Nginx #########\n"
sudo apt install nginx -y
sudo apt auto-remove

echo "\nTry opening Ubuntu_IP:80; You should see default Nginx Welcome Page\n"

echo "\n####### Configuring your custom Nginx App -NginxApp ########\n"
cd /var/www
sudo mkdir NginxApp
cd NginxApp
sudo echo "<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Welcome to Nginx App Made by You for You</title>
</head>
<body>
    <h1>Hello, Nginx!</h1>
    <p>Time to test</p>
</body>
</html>" > index.html

cd /etc/nginx/sites-enabled
sudo echo "server {
       listen 81;
       listen [::]:81;

       server_name example.ubuntu.com;

       root /var/www/NginxApp;
       index index.html;

       location / {
               try_files $uri $uri/ =404;
       }
       }" >  NginxApp
sudo systemctl restart nginx
echo "\nInitial Setup completed. \nTry accessing Ubuntu_IP:81; You should see Nginx page. Enjoy!!"
