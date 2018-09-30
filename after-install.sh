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
if [[ "${EUID}" -ne 0 ]]; then
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
echo -e "\n** PostgreSQL **"
echo -e '[i] (Re)starting PostgreSQL Service \n'
systemctl restart postgresql
sleep 1s
echo -e "** Okay... We're done! **\n"

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
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Enabling default OS repositories"

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

## Update
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Updating APT information"
apt -qq update
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" There is an issue getting updates${RESET}" 1>&2
  echo -e " ${YELLOW}[i]${RESET} Check your local network repository information:\n" 
  curl -sI http://http.kali.org/README
  exit 1
fi

sleep 5s
## Install VMware tools
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing open-vm-tools and shizzle."
apt -qq install open-vm-tools open-vm-tools-desktop fuse make -y

sleep 5s
## Setting Time
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ntpdate"
apt -y -qq install ntp ntpdate
ntpdate -b -s -u pool.ntp.org
systemctl restart ntp
systemctl enable ntp 2>/dev/null
start_time=$(date +%s)

sleep 5s
## Full update
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating OS"
for FILE in clean autoremove; do apt -y -qq "${FILE}"; done
export DEBIAN_FRONTEND=noninteractive
apt -qq update && APT_LISTCHANGES_FRONTEND=none apt -o Dpkg::Options::="--force-confnew" -y dist-upgrade --fix-missing 2>&1

for FILE in clean autoremove; do apt -y -qq "${FILE}"; done

sleep 5s
## Install kernel headers
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}kernel headers${RESET}"
apt -y -qq install gcc "linux-headers-$(uname -r)"
if [[ $? -ne 0 ]]; then
  echo -e ' '${RED}'[!]'" There was an issue installing kernel headers${RESET}" 1>&2
  exit 1
fi

sleep 5s
## Install "kali full" meta packages (default tool selection)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing kali-linux-full meta-package"
apt -y -qq install kali-linux-full

sleep 5s
## Configure GRUB
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring GRUB boot manager"
grubTimeout=5
(dmidecode | grep -iq virtual) && grubTimeout=1
file=/etc/default/grub; [ -e "${file}" ] && cp -n $file{,.bkup}
sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT='${grubTimeout}'/' "${file}"
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="vga=0x0318"/' "${file}"
update-grub

sleep 5s
## Clean the system
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Cleaning the system"

##- Clean package manager
for FILE in clean autoremove; do apt -y -qq "${FILE}"; done
apt -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')

##- Update slocate database
updatedb

##- Reset folder location
cd ~/ &>/dev/null

##- Remove any history files (as they could contain sensitive info)
history -cw 2>/dev/null
for i in $(cut -d: -f6 /etc/passwd | sort -u); do
  [ -e "${i}" ] && find "${i}" -type f -name '.*_history' -delete
done

## Time taken
finish_time=$(date +%s)
echo -e "\n\n ${YELLOW}[i]${RESET} Time (roughly) taken: ${YELLOW}$(( $(( finish_time - start_time )) / 60 )) minutes${RESET}"

## Done!
echo -e "\n ${YELLOW}[!]${RESET} So. We're done. Please:
echo -e " ${YELLOW}[i]${RESET} + Setup git:   ${YELLOW}git config --global user.name <name>;git config --global user.email <email>${RESET}"
echo -e " ${YELLOW}[i]${RESET} + ${YELLOW}Reboot${RESET}"
echo -e " ${YELLOW}[i]${RESET} + Take a snapshot"

echo -e '\n'${BLUE}'[*]'${RESET}' '${BOLD}'Done!'${RESET}'\n\a'
exit 0
