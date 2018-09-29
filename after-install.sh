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
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Disable Gnome shit."
timeout 5 killall -w /usr/lib/apt/methods/http > /dev/null 2>&1
xset s 0 0
xset s off
gsettings set org.gnome.desktop.session idle-delay 0

sleep 5s
## Check internet access

