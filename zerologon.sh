#!/bin/bash
echo -ne "\e]2;Metasploit\a"			#change terminal window title to be grabbed by auto script
rm -rf /var/www/html/upload/*			#empty files from previous demos
rm -f /home/aptuser/*				#empty files from previous demos
service apache2 start				#start HTTP server
service vsftpd start				#start FTP server
/DemoTools/aptdemo/sendemail.sh			#send phishing email
