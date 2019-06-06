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
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal
STAGE=0
TOTAL=$( grep '(${STAGE}/${TOTAL})' $0 | wc -l );(( TOTAL-- ))

## Are we root?
if [[ "${EUID}" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" Run this as ${RED}root${RESET}. Quitting now..." 1>&2
  exit 1
else
  echo -e " ${GREEN}[*]${RESET} ${BOLD}Making your life easier. Installing and configuring what you thought was useful.${RESET}"
  sleep 3s
fi

export DISPLAY=:0.0
export TERM=xterm

## Disable Gnome shizzle
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Disable Gnome shit..."
timeout 5 killall -w /usr/lib/apt/methods/http > /dev/null 2>&1
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
function apt-updater {
	apt update &&
	apt dist-upgrade -Vy &&
	apt autoremove -y &&
	apt autoclean &&
	apt clean
	}

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

##- Tor
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Installing TOR"
echo -e "deb https://deb.torproject.org/torproject.org stretch main" > /etc/apt/sources.list.d/tor.list
echo -e "deb-src https://deb.torproject.org/torproject.org stretch main" >> /etc/apt/sources.list.d/tor.list
wget -q -O- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | apt-key add -
apt -qq update
apt -qq install tor deb.torproject.org-keyring

sleep 5s
## Install VMware tools
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing open-vm-tools and shizzle."
apt -qq install open-vm-tools open-vm-tools-desktop fuse make htop gettext -y

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
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing kernel headers"
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
## Reconfigure SSH
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL})  Re-configuring SSH"
pushd /etc/ssh/
dpkg-reconfigure openssh-server
systemctl enable ssh
systemctl restart ssh
popd

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
## Get all for Bloodhound
((STAGE++)); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Cloning all for Bloodhound" 
mkdir -p /opt/Bloodhound
pushd /opt/Bloodhound
git clone https://github.com/BloodHoundAD/BloodHound.git
git clone https://github.com/BloodHoundAD/BloodHound-Tools.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
pip install bloodhound
popd

sleep 5s
## Cloning basic tools
((STAGE++)); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Cloning Github Repos" 
pushd /opt
git clone https://github.com/mubix/pykek.git
git clone https://github.com/vrana/adminer.git
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
git clone https://github.com/chokepoint/azazel.git
git clone https://github.com/jseidl/Babadook.git
git clone https://github.com/NetSPI/cmdsql.git
git clone https://github.com/galkan/crowbar
git clone https://github.com/Hood3dRob1n/CVE-2016-3714.git
git clone https://github.com/gebl/dirtycow-docker-vdso.git
git clone https://github.com/breenmachine/dnsftp.git
git clone https://github.com/mfontanini/dot11decrypt.git
git clone https://github.com/BlackMathIT/Esteemaudit-Metasploit.git
git clone https://github.com/offensive-security/exploit-database-papers.git
git clone https://github.com/fuzzdb-project/fuzzdb.git
git clone https://github.com/aleaxit/gmpy.git
git clone https://github.com/nullmode/gnmap-parser.git
git clone https://github.com/OJ/gobuster.git
git clone https://github.com/wireghoul/graudit.git
git clone https://github.com/NerdyProjects/hostapd-wpe-extended.git
git clone https://github.com/SilentGhostX/HT-WPS-Breaker.git
git clone https://github.com/inquisb/icmpsh.git
git clone https://github.com/gojhonny/InSpy.git
git clone https://github.com/matthiaskaiser/jmet.git
git clone https://github.com/rastating/jooforce.git
git clone https://github.com/libyal/libesedb.git
git clone https://github.com/hellman/libnum.git
git clone https://github.com/xillwillx/MiniReverse_Shell_With_Parameters.git
git clone https://github.com/worawit/MS17-010.git
git clone https://github.com/sullo/nikto.git
git clone https://github.com/codingo/NoSQLMap.git
git clone https://github.com/csababarta/ntdsxtract.git
git clone https://github.com/superkojiman/onetwopunch.git
git clone https://github.com/adon90/openssl_wfuzz.git
git clone https://github.com/s7ephen/pfi.git
git clone https://github.com/rofl0r/proxychains-ng.git
git clone https://github.com/n1nj4sec/pupy.git
git clone https://github.com/infodox/python-pty-shells.git
git clone https://github.com/codingo/Reconnoitre.git
git clone https://github.com/sensepost/reGeorg.git
git clone https://github.com/trustedsec/ridenum
git clone https://github.com/ripsscanner/rips.git
git clone https://github.com/foxglovesec/RottenPotato.git
git clone https://github.com/Ganapati/RsaCtfTool.git
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/Vozzie/uacscript.git
git clone https://github.com/trustedsec/unicorn.git
git clone https://github.com/tennc/webshell.git
git clone https://github.com/sophron/wifiphisher.git
git clone https://github.com/dxa4481/WPA2-HalfHandshake-Crack.git
git clone https://github.com/frohoff/ysoserial.git
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
git clone https://github.com/kennyn510/wpa2-wordlists.git
popd

sleep 5s
## Setting dock things
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Setting the Dock" 
gsettings set org.gnome.shell.extensions.dash-to-dock dock-fixed true
gsettings set org.gnome.shell.extensions.dash-to-dock autohide false
gsettings set org.gnome.shell.extensions.dash-to-dock intellihide false
gsettings set org.gnome.shell.extensions.dash-to-dock intellihide-mode 'ALL_WINDOWS'
gsettings set org.gnome.shell.extensions.dash-to-dock height-fraction 1
gsettings set org.gnome.shell.extensions.dash-to-dock transparency-mode FIXED
gsettings set org.gnome.shell.extensions.dash-to-dock dash-max-icon-size 28

sleep 5s
## RubberDucky tools for offline payload generation
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Cloning Rubberducky tools" 
pushd /opt
git clone https://github.com/hak5darren/USB-Rubber-Ducky
popd

sleep 5s
##
## This is the last section, keep at bottom!
##

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
echo -e "\n ${YELLOW}[i]${RESET} So. We're done. Please:"
echo -e " ${YELLOW}[i]${RESET} + Setup git: git config --global user.name <name>;git config --global user.email <email>"
echo -e " ${YELLOW}[i]${RESET} + Reboot"
echo -e " ${YELLOW}[i]${RESET} + Take a snapshot"
echo -e " ${YELLOW}[i]${RESET} + ${YELLOW}If the update installed new kernel modules, re-run the script after reboot for fixes!!${RESET}"

echo -e '\n'${GREEN}'[*]'${RESET}' '${BOLD}'Done!'${RESET}'\n\a'
exit 0
