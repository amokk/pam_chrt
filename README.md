setup:
apt-get install build-essential libpam0g-dev

kompilacia:
rm -f pam_chrt.*o; gcc -fPIC -c pam_chrt.c; gcc -shared -o pam_chrt.so pam_chrt.o -lpam

run:
1. skopiruj skompilovanu kniznicu pam_chrt.so do /lib/security (po novom do /lib/x86_64-linux-gnu/security/)
2. uprav napr /etc/pam.d/sshd a pridaj riadok pod @common-auth:
   auth   required  pam_chrt.so debug
3. restartni sshd
4. od teraz iba useri ktori su v /root/myfile sa mozu prihlasit cez ssh
