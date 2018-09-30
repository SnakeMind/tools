#!/bin/bash
#-Metadata----------------------------------------------------------#
#  Filename: after-install.sh           (Updated: 2018-09-29)       #
#-Info--------------------------------------------------------------#
#  Post-install script for Kali Linux Rolling x64                   #
#-Author(s)---------------------------------------------------------#
#  SnakeMind                                                        #
#-Notes-------------------------------------------------------------#
#  Run as root straight after a clean install of Kali Rolling       #
#                                                                   #
#          ** This script is written for -my- needs **              #
#-------------------------------------------------------------------#

## (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal
STAGE=0
TOTAL=$( grep '(${STAGE}/${TOTAL})' $0 | wc -l );(( TOTAL-- ))

## Are we root?
if [[ "${EUID}" -ne 0]]; then
  echo -e ' '${RED}'[!]'${RESET}" Run this as ${RED}root${RESET}. Quitting now..." 1>&2
  exit 1
else
  echo -e " ${BLUE}[*]${RESET} ${BOLD}Making your life easier. Installing and configuring what you thought was useful.${RESET}"
  sleep 3s
fi

export DISPLAY=:0.0
export TERM=xterm

## Disable Gnome shizzle
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Disable Gnome shit..."
timeout 5 killall -w /usr/lib/apt/methods/http > /dev/null 2>&1
xset s 0 0
xset s off
gsettings set org.gnome.desktop.session idle-delay 0

sleep 5s
## Check internet access
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking Internet Access..."
for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${RED}Issues with the internet? Go fix..." 1>&2
  exit 1
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
fi

## Create afterboot file
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Placing files for afterboot and aliases."

##- Shared Folders script
file=/usr/local/sbin/mount-shared-folders; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" \
    || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash

vmware-hgfsclient | while read folder; do
  echo "[i] Mounting \${folder}   (/mnt/hgfs/\${folder})"
  mkdir -p "/mnt/hgfs/\${folder}"
  umount -f "/mnt/hgfs/\${folder}" 2>/dev/null
  vmhgfs-fuse -o allow_other -o auto_unmount ".host:/\${folder}" "/mnt/hgfs/\${folder}"
done

sleep 2s
EOF
chmod +x "${file}"

##- Afterboot file
file=/root/afterboot.sh; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" \
    || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash

echo -e "** Mounting Stack **"
bash /usr/local/sbin/mount-shared-folders
echo -e "** PostgreSQL **"
systemctl restart postgresql
sleep 1s
echo ' '
echo "** Okay... We're done! **\n"

EOF
chmod +x "${file}"

sleep 2s
##- Create .bash_alias file
file=/root/.bash_aliases; [ -e "${file}" ] && cp -n $file{,.bkup}
cat <<EOF > "${file}" \
    || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
alias afterboot='bash /root/afterboot.sh'
alias nmapinitial='nmap -sS -sV -A -v -oA initial '
alias nmapfull='nmap -sS -sV -A -v -p- -oA full '
EOF

sleep 5s
## Enable default network repositories ~ http://docs.kali.org/general-use/kali-linux-sources-list-repositories
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Enabling default OS ${GREEN}network repositories${RESET}"

##- Add network repositories
file=/etc/apt/sources.list; [ -e "${file}" ] && cp -n $file{,.bkup}
([[ -e "${file}" && "$(tail -c 1 ${file})" != "" ]]) && echo >> "${file}"

##- Main
grep -q '^deb .* kali-rolling' "${file}" 2>/dev/null \
  || echo -e "\n\n# Kali Rolling\ndeb http://http.kali.org/kali kali-rolling main contrib non-free" >> "${file}"

##- Source
grep -q '^deb-src .* kali-rolling' "${file}" 2>/dev/null \
  || echo -e "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> "${file}"

##- Disable CD repositories
sed -i '/kali/ s/^\( \|\t\|\)deb cdrom/#deb cdrom/g' "${file}"

##- incase we were interrupted
dpkg --configure -a
