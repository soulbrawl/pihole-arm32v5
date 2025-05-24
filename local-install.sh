#!/usr/bin/env bash
set -e
export PATH+=':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

DNS_SERVERS=$(cat << EOM
Google (ECS, DNSSEC);8.8.8.8;8.8.4.4;2001:4860:4860:0:0:0:0:8888;2001:4860:4860:0:0:0:0:8844
OpenDNS (ECS, DNSSEC);208.67.222.222;208.67.220.220;2620:119:35::35;2620:119:53::53
Level3;4.2.2.1;4.2.2.2;;
Comodo;8.26.56.26;8.20.247.20;;
DNS.WATCH (DNSSEC);84.200.69.80;84.200.70.40;2001:1608:10:25:0:0:1c04:b12f;2001:1608:10:25:0:0:9249:d69b
Quad9 (filtered, DNSSEC);9.9.9.9;149.112.112.112;2620:fe::fe;2620:fe::9
Quad9 (unfiltered, no DNSSEC);9.9.9.10;149.112.112.10;2620:fe::10;2620:fe::fe:10
Quad9 (filtered, ECS, DNSSEC);9.9.9.11;149.112.112.11;2620:fe::11;2620:fe::fe:11
Cloudflare (DNSSEC);1.1.1.1;1.0.0.1;2606:4700:4700::1111;2606:4700:4700::1001
EOM
)

# Location for final installation log storage
installLogLoc="/etc/pihole/install.log"
# This is an important file as it contains information specific to the machine it's being installed on
setupVars="/etc/pihole/setupVars.conf"
# Pi-hole uses lighttpd as a Web server, and this is the config file for it
lighttpdConfig="/etc/lighttpd/lighttpd.conf"
# This is a file used for the colorized output
coltable="/opt/pihole/COL_TABLE"

# Root of the web server
webroot="/var/www/html"

# Local path
LOCAL_FTL="FTL-5.16.1/pihole-FTL-armv5-linux-gnueabi"
LOCAL_WEB="web-5.13"
LOCAL_PI_HOLE="pi-hole-5.11.4"

PIHOLE_DNS_1="1.1.1.1"
PIHOLE_DNS_2="1.0.0.1"
PIHOLE_DNS_3="8.8.8.8"
PIHOLE_DNS_4="8.8.4.4"
INSTALL_WEB_SERVER=true
QUERY_LOGGING=true

webInterfaceDir="${webroot}/admin"
# List of pihole scripts, stored in an array
PI_HOLE_FILES=(chronometer list piholeDebug piholeLogFlush setupLCD update version gravity uninstall webpage)
# This directory is where the Pi-hole scripts will be installed
PI_HOLE_INSTALL_DIR="/opt/pihole"
PI_HOLE_CONFIG_DIR="/etc/pihole"
PI_HOLE_BIN_DIR="/usr/local/bin"
PI_HOLE_BLOCKPAGE_DIR="${webroot}/pihole"
if [ -z "$useUpdateVars" ]; then
    useUpdateVars=false
fi

adlistFile="/etc/pihole/adlists.list"
# Pi-hole needs an IP address; to begin, these variables are empty since we don't know what the IP is until this script can run
IPV4_ADDRESS=${IPV4_ADDRESS}
IPV6_ADDRESS=${IPV6_ADDRESS}
# Give settings their default values. These may be changed by prompts later in the script.
QUERY_LOGGING=true
INSTALL_WEB_INTERFACE=true
PRIVACY_LEVEL=0
CACHE_SIZE=10000

if [ -z "${USER}" ]; then
    USER="$(id -un)"
fi

# dialog dimensions: Let dialog handle appropriate sizing.
r=20
c=70

reconfigure=false
runUnattended=false
INSTALL_WEB_SERVER=true
# Check arguments for the undocumented flags
for var in "$@"; do
    case "$var" in
        "--reconfigure" ) reconfigure=true;;
        "--unattended" ) runUnattended=true;;
        "--disable-install-webserver" ) INSTALL_WEB_SERVER=false;;
    esac
done

# If the color table file exists,
if [[ -f "${coltable}" ]]; then
    # source it
    source "${coltable}"
# Otherwise,
else
    # Set these values so the installer can still run in color
    COL_NC='\e[0m' # No Color
    COL_LIGHT_GREEN='\e[1;32m'
    COL_LIGHT_RED='\e[1;31m'
    TICK="[${COL_LIGHT_GREEN}✓${COL_NC}]"
    CROSS="[${COL_LIGHT_RED}✗${COL_NC}]"
    INFO="[i]"
    # shellcheck disable=SC2034
    DONE="${COL_LIGHT_GREEN} done!${COL_NC}"
    OVER="\\r\\033[K"
fi

# A simple function that just echoes out our logo in ASCII format
# This lets users know that it is a Pi-hole, LLC product
show_ascii_berry() {
    echo -e "
        ${COL_LIGHT_GREEN}.;;,.
        .ccccc:,.
         :cccclll:.      ..,,
          :ccccclll.   ;ooodc
           'ccll:;ll .oooodc
             .;cll.;;looo:.
                 ${COL_LIGHT_RED}.. ','.
                .',,,,,,'.
              .',,,,,,,,,,.
            .',,,,,,,,,,,,....
          ....''',,,,,,,'.......
        .........  ....  .........
        ..........      ..........
        ..........      ..........
        .........  ....  .........
          ........,,,,,,,'......
            ....',,,,,,,,,,,,.
               .',,,,,,,,,'.
                .',,,,,,'.
                  ..'''.${COL_NC}
"
}

is_command() {
    # Checks to see if the given command (passed as a string argument) exists on the system.
    # The function returns 0 (success) if the command exists, and 1 if it doesn't.
    local check_command="$1"

    command -v "${check_command}" >/dev/null 2>&1
}

# This function waits for dpkg to unlock, which signals that the previous apt-get command has finished.
test_dpkg_lock() {
    i=0
    printf "  %b Waiting for package manager to finish (up to 30 seconds)\\n" "${INFO}"
    # fuser is a program to show which processes use the named files, sockets, or filesystems
    # So while the lock is held,
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1
    do
        # we wait half a second,
        sleep 0.5
        # increase the iterator,
        ((i=i+1))
        # exit if waiting for more then 30 seconds
        if [[ $i -gt 60 ]]; then
            printf "  %b %bError: Could not verify package manager finished and released lock. %b\\n" "${CROSS}" "${COL_LIGHT_RED}" "${COL_NC}"
            printf "       Attempt to install packages manually and retry.\\n"
            exit 1;
        fi
    done
    # and then report success once dpkg is unlocked.
    return 0
}

# Compatibility
package_manager_detect() {
    # TODO - pull common packages for both distributions out into a common variable, then add
    # the distro-specific ones below.

    # First check to see if apt-get is installed.
    if is_command apt-get ; then
        # Set some global variables here
        # We don't set them earlier since the installed package manager might be rpm, so these values would be different
        PKG_MANAGER="apt-get"
        # A variable to store the command used to update the package cache
        UPDATE_PKG_CACHE="${PKG_MANAGER} update"
        # The command we will use to actually install packages
        PKG_INSTALL=("${PKG_MANAGER}" -qq --no-install-recommends install)
        # grep -c will return 1 if there are no matches. This is an acceptable condition, so we OR TRUE to prevent set -e exiting the script.
        PKG_COUNT="${PKG_MANAGER} -s -o Debug::NoLocking=true upgrade | grep -c ^Inst || true"
        # Update package cache
        update_package_cache || exit 1
        # Check for and determine version number (major and minor) of current php install
        local phpVer="php"
        if is_command php ; then
            phpVer="$(php <<< "<?php echo PHP_VERSION ?>")"
            # Check if the first character of the string is numeric
            if [[ ${phpVer:0:1} =~ [1-9] ]]; then
                printf "  %b Existing PHP installation detected : PHP version %s\\n" "${INFO}" "${phpVer}"
                printf -v phpInsMajor "%d" "$(php <<< "<?php echo PHP_MAJOR_VERSION ?>")"
                printf -v phpInsMinor "%d" "$(php <<< "<?php echo PHP_MINOR_VERSION ?>")"
                phpVer="php$phpInsMajor.$phpInsMinor"
            else
                printf "  %b No valid PHP installation detected!\\n" "${CROSS}"
                printf "  %b PHP version : %s\\n" "${INFO}" "${phpVer}"
                printf "  %b Aborting installation.\\n" "${CROSS}"
                exit 1
            fi
        fi
        # Packages required to perform the os_check (stored as an array)
        OS_CHECK_DEPS=(grep dnsutils)
        # Packages required to run this install script (stored as an array)
        INSTALLER_DEPS=(git iproute2 dialog ca-certificates)
        # Packages required to run Pi-hole (stored as an array)
        PIHOLE_DEPS=(cron curl iputils-ping psmisc sudo unzip idn2 libcap2-bin dns-root-data libcap2 netcat-openbsd procps)
        # Packages required for the Web admin interface (stored as an array)
        # It's useful to separate this from Pi-hole, since the two repos are also setup separately
        PIHOLE_WEB_DEPS=(lighttpd "${phpVer}-common" "${phpVer}-cgi" "${phpVer}-sqlite3" "${phpVer}-xml" "${phpVer}-intl")
        # Prior to PHP8.0, JSON functionality is provided as dedicated module, required by Pi-hole AdminLTE: https://www.php.net/manual/json.installation.php
        if [[ -z "${phpInsMajor}" || "${phpInsMajor}" -lt 8 ]]; then
            PIHOLE_WEB_DEPS+=("${phpVer}-json")
        fi
        # The Web server user,
        LIGHTTPD_USER="www-data"
        # group,
        LIGHTTPD_GROUP="www-data"
        # and config file
        LIGHTTPD_CFG="lighttpd.conf.debian"

    # If apt-get is not found, check for rpm.
    elif is_command rpm ; then
        # Then check if dnf or yum is the package manager
        if is_command dnf ; then
            PKG_MANAGER="dnf"
        else
            PKG_MANAGER="yum"
        fi

        # These variable names match the ones for apt-get. See above for an explanation of what they are for.
        PKG_INSTALL=("${PKG_MANAGER}" install -y)
        # CentOS package manager returns 100 when there are packages to update so we need to || true to prevent the script from exiting.
        PKG_COUNT="${PKG_MANAGER} check-update | egrep '(.i686|.x86|.noarch|.arm|.src)' | wc -l || true"
        OS_CHECK_DEPS=(grep bind-utils)
        INSTALLER_DEPS=(git dialog iproute newt procps-ng which chkconfig ca-certificates)
        PIHOLE_DEPS=(cronie curl findutils sudo unzip libidn2 psmisc libcap nmap-ncat)
        PIHOLE_WEB_DEPS=(lighttpd lighttpd-fastcgi php-common php-cli php-pdo php-xml php-json php-intl)
        LIGHTTPD_USER="lighttpd"
        LIGHTTPD_GROUP="lighttpd"
        LIGHTTPD_CFG="lighttpd.conf.fedora"

    # If neither apt-get or yum/dnf package managers were found
    else
        # we cannot install required packages
        printf "  %b No supported package manager found\\n" "${CROSS}"
        # so exit the installer
        exit
    fi
}

find_IPv4_information() {
    # Detects IPv4 address used for communication to WAN addresses.
    # Accepts no arguments, returns no values.

    # Named, local variables
    local route
    local IPv4bare

    # Find IP used to route to outside world by checking the the route to Google's public DNS server
    route=$(ip route get 8.8.8.8)

    # Get just the interface IPv4 address
    # shellcheck disable=SC2059,SC2086
    # disabled as we intentionally want to split on whitespace and have printf populate
    # the variable with just the first field.
    printf -v IPv4bare "$(printf ${route#*src })"
    # Get the default gateway IPv4 address (the way to reach the Internet)
    # shellcheck disable=SC2059,SC2086
    printf -v IPv4gw "$(printf ${route#*via })"

    if ! valid_ip "${IPv4bare}" ; then
        IPv4bare="127.0.0.1"
    fi

    # Append the CIDR notation to the IP address, if valid_ip fails this should return 127.0.0.1/8
    IPV4_ADDRESS=$(ip -oneline -family inet address show | grep "${IPv4bare}/" |  awk '{print $4}' | awk 'END {print}')
}

# Get available interfaces that are UP
get_available_interfaces() {
    # There may be more than one so it's all stored in a variable
    availableInterfaces=$(ip --oneline link show up | grep -v "lo" | grep -v "docker" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1)
}

# A function that lets the user pick an interface to use with Pi-hole
chooseInterface() {
    # Turn the available interfaces into a string so it can be used with dialog
    local interfacesList
    # Number of available interfaces
    local interfaceCount

    # POSIX compliant way to get the number of elements in an array
    interfaceCount=$(printf "%s\n" "${availableInterfaces}" | wc -l)

    # If there is one interface,
    if [[ "${interfaceCount}" -eq 1 ]]; then
        # Set it as the interface to use since there is no other option
        PIHOLE_INTERFACE="${availableInterfaces}"
    # Otherwise,
    else
        # Set status for the first entry to be selected
        status="ON"

        # While reading through the available interfaces
        for interface in ${availableInterfaces}; do
            # Put all these interfaces into a string
            interfacesList="${interfacesList}${interface} available ${status} "
            # All further interfaces are deselected
            status="OFF"
        done
        # shellcheck disable=SC2086
        # Disable check for double quote here as we are passing a string with spaces
        PIHOLE_INTERFACE=$(dialog --no-shadow --keep-tite --output-fd 1 \
            --cancel-label "Exit" --ok-label "Select" \
            --radiolist "Choose An Interface (press space to toggle selection)" \
            ${r} ${c} "${interfaceCount}" ${interfacesList})

        result=$?
        case ${result} in
            "${DIALOG_CANCEL}"|"${DIALOG_ESC}")
                # Show an error message and exit
                printf "  %b %s\\n" "${CROSS}" "No interface selected, exiting installer"
                exit 1
                ;;
        esac

        printf "  %b Using interface: %s\\n" "${INFO}" "${PIHOLE_INTERFACE}"
    fi
}

# This lets us prefer ULA addresses over GUA
# This caused problems for some users when their ISP changed their IPv6 addresses
# See https://github.com/pi-hole/pi-hole/issues/1473#issuecomment-301745953
testIPv6() {
    # first will contain fda2 (ULA)
    printf -v first "%s" "${1%%:*}"
    # value1 will contain 253 which is the decimal value corresponding to 0xFD
    value1=$(( (0x$first)/256 ))
    # value2 will contain 162 which is the decimal value corresponding to 0xA2
    value2=$(( (0x$first)%256 ))
    # the ULA test is testing for fc00::/7 according to RFC 4193
    if (( (value1&254)==252 )); then
        # echoing result to calling function as return value
        echo "ULA"
    fi
    # the GUA test is testing for 2000::/3 according to RFC 4291
    if (( (value1&112)==32 )); then
        # echoing result to calling function as return value
        echo "GUA"
    fi
    # the LL test is testing for fe80::/10 according to RFC 4193
    if (( (value1)==254 )) && (( (value2&192)==128 )); then
        # echoing result to calling function as return value
        echo "Link-local"
    fi
}

find_IPv6_information() {
    # Detects IPv6 address used for communication to WAN addresses.
    IPV6_ADDRESSES=($(ip -6 address | grep 'scope global' | awk '{print $2}'))

    # For each address in the array above, determine the type of IPv6 address it is
    for i in "${IPV6_ADDRESSES[@]}"; do
        # Check if it's ULA, GUA, or LL by using the function created earlier
        result=$(testIPv6 "$i")
        # If it's a ULA address, use it and store it as a global variable
        [[ "${result}" == "ULA" ]] && ULA_ADDRESS="${i%/*}"
        # If it's a GUA address, use it and store it as a global variable
        [[ "${result}" == "GUA" ]] && GUA_ADDRESS="${i%/*}"
        # Else if it's a Link-local address, we cannot use it, so just continue
    done

    # Determine which address to be used: Prefer ULA over GUA or don't use any if none found
    # If the ULA_ADDRESS contains a value,
    if [[ ! -z "${ULA_ADDRESS}" ]]; then
        # set the IPv6 address to the ULA address
        IPV6_ADDRESS="${ULA_ADDRESS}"
        # Show this info to the user
        printf "  %b Found IPv6 ULA address\\n" "${INFO}"
    # Otherwise, if the GUA_ADDRESS has a value,
    elif [[ ! -z "${GUA_ADDRESS}" ]]; then
        # Let the user know
        printf "  %b Found IPv6 GUA address\\n" "${INFO}"
        # And assign it to the global variable
        IPV6_ADDRESS="${GUA_ADDRESS}"
    # If none of those work,
    else
        printf "  %b Unable to find IPv6 ULA/GUA address\\n" "${INFO}"
        # So set the variable to be empty
        IPV6_ADDRESS=""
    fi
}

# A function to collect IPv4 and IPv6 information of the device
collect_v4andv6_information() {
    find_IPv4_information
    # Echo the information to the user
    printf "  %b IPv4 address: %s\\n" "${INFO}" "${IPV4_ADDRESS}"
    # if `dhcpcd` is used offer to set this as static IP for the device
    if [[ -f "/etc/dhcpcd.conf" ]]; then
        # configure networking via dhcpcd
        getStaticIPv4Settings
    fi
    find_IPv6_information
    printf "  %b IPv6 address: %s\\n" "${INFO}" "${IPV6_ADDRESS}"
}

getStaticIPv4Settings() {
    # Local, named variables
    local ipSettingsCorrect
    local DHCPChoice
    # Ask if the user wants to use DHCP settings as their static IP
    # This is useful for users that are using DHCP reservations; we can use the information gathered
    DHCPChoice=$(dialog --no-shadow --keep-tite --output-fd 1 \
        --cancel-label "Exit" --ok-label "Continue" \
        --backtitle "Calibrating network interface" \
        --title "Static IP Address" \
        --menu "Do you want to use your current network settings as a static address?\\n \
            IP address:    ${IPV4_ADDRESS}\\n \
            Gateway:       ${IPv4gw}\\n" \
            "${r}" "${c}" 3 \
                "Yes" "Set static IP using current values" \
                "No" "Set static IP using custom values" \
                "Skip" "I will set a static IP later, or have already done so")

        result=$?
        case ${result} in
            "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
            printf "  %b Cancel was selected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
            exit 1
            ;;
        esac

        case ${DHCPChoice} in
            "Skip")
                return
                ;;
            "Yes")
            # If they choose yes, let the user know that the IP address will not be available via DHCP and may cause a conflict.
            dialog --no-shadow --keep-tite \
                --cancel-label "Exit" \
                --backtitle "IP information" \
                --title "FYI: IP Conflict" \
                --msgbox "\\nIt is possible your router could still try to assign this IP to a device, which would cause a conflict\
But in most cases the router is smart enough to not do that.\
If you are worried, either manually set the address, or modify the DHCP reservation pool so it does not include the IP you want.\
It is also possible to use a DHCP reservation, but if you are going to do that, you might as well set a static address."\
                "${r}" "${c}" && result=0 || result=$?

                case ${result} in
                    "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
                    printf "  %b Cancel was selected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
                    exit 1
                    ;;
                esac
            ;;

            "No")
            # Otherwise, we need to ask the user to input their desired settings.
            # Start by getting the IPv4 address (pre-filling it with info gathered from DHCP)
            # Start a loop to let the user enter their information with the chance to go back and edit it if necessary
            ipSettingsCorrect=false
            until [[ "${ipSettingsCorrect}" = True ]]; do

                # Ask for the IPv4 address
                _staticIPv4Temp=$(dialog --no-shadow --keep-tite --output-fd 1 \
                    --cancel-label "Exit" \
                    --ok-label "Continue" \
                    --backtitle "Calibrating network interface" \
                    --title "IPv4 Address" \
                    --form "\\nEnter your desired IPv4 address" \
                    "${r}" "${c}" 0 \
                        "IPv4 Address:" 1 1 "${IPV4_ADDRESS}" 1 15 19 0 \
                        "IPv4 Gateway:" 2 1 "${IPv4gw}" 2 15 19 0)

                result=$?
                case ${result} in
                    "${DIALOG_CANCEL}" | "${DIALOG_ESC}")
                    printf "  %b Cancel was selected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
                    exit 1
                    ;;
                esac

                IPV4_ADDRESS=${_staticIPv4Temp%$'\n'*}
                IPv4gw=${_staticIPv4Temp#*$'\n'}

                # Give the user a chance to review their settings before moving on
                dialog --no-shadow --keep-tite \
                    --no-label "Edit IP" \
                    --backtitle "Calibrating network interface" \
                    --title "Static IP Address" \
                    --defaultno \
                    --yesno "Are these settings correct?
                        IP address: ${IPV4_ADDRESS}
                        Gateway:    ${IPv4gw}" \
                    "${r}" "${c}" && ipSettingsCorrect=True
            done
            ;;
       esac
       setDHCPCD
}

# Configure networking via dhcpcd
setDHCPCD() {
    # Check if the IP is already in the file
    if grep -q "${IPV4_ADDRESS}" /etc/dhcpcd.conf; then
        printf "  %b Static IP already configured\\n" "${INFO}"
    # If it's not,
    else
        # we can append these lines to dhcpcd.conf to enable a static IP
        echo "interface ${PIHOLE_INTERFACE}
        static ip_address=${IPV4_ADDRESS}
        static routers=${IPv4gw}
        static domain_name_servers=${PIHOLE_DNS_1} ${PIHOLE_DNS_2}" | tee -a /etc/dhcpcd.conf >/dev/null
        # Then use the ip command to immediately set the new address
        ip addr replace dev "${PIHOLE_INTERFACE}" "${IPV4_ADDRESS}"
        # Also give a warning that the user may need to reboot their system
        printf "  %b Set IP address to %s\\n" "${TICK}" "${IPV4_ADDRESS%/*}"
        printf "  %b You may need to restart after the install is complete\\n" "${INFO}"
    fi
}

# Check an IP address to see if it is a valid one
valid_ip() {
    # Local, named variables
    local ip=${1}
    local stat=1

    # Regex matching one IPv4 component, i.e. an integer from 0 to 255.
    # See https://tools.ietf.org/html/rfc1340
    local ipv4elem="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|0)";
    # Regex matching an optional port (starting with '#') range of 1-65536
    local portelem="(#(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))?";
    # Build a full IPv4 regex from the above subexpressions
    local regex="^${ipv4elem}\\.${ipv4elem}\\.${ipv4elem}\\.${ipv4elem}${portelem}$"

    # Evaluate the regex, and return the result
    [[ $ip =~ ${regex} ]]

    stat=$?
    return "${stat}"
}

valid_ip6() {
    local ip=${1}
    local stat=1

    # Regex matching one IPv6 element, i.e. a hex value from 0000 to FFFF
    local ipv6elem="[0-9a-fA-F]{1,4}"
    # Regex matching an IPv6 CIDR, i.e. 1 to 128
    local v6cidr="(\\/([1-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])){0,1}"
    # Regex matching an optional port (starting with '#') range of 1-65536
    local portelem="(#(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))?";
    # Build a full IPv6 regex from the above subexpressions
    local regex="^(((${ipv6elem}))*((:${ipv6elem}))*::((${ipv6elem}))*((:${ipv6elem}))*|((${ipv6elem}))((:${ipv6elem})){7})${v6cidr}${portelem}$"

    # Evaluate the regex, and return the result
    [[ ${ip} =~ ${regex} ]]

    stat=$?
    return "${stat}"
}

setDefaultBlocklist() {
    if [ ! -f "${adlistFile}" ]; then
        install -m 644 /dev/null "${adlistFile}"
    else
        chmod 644 "${adlistFile}"
    fi
    echo "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" >> "${adlistFile}"
}

# Used only in unattended setup
# If there is already the adListFile, we keep it, else we create it using all default lists
installDefaultBlocklists() {
    # In unattended setup, could be useful to use userdefined blocklist.
    # If this file exists, we avoid overriding it.
    if [[ -f "${adlistFile}" ]]; then
        return;
    fi
        echo "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" >> "${adlistFile}"
}

# Check if /etc/dnsmasq.conf is from pi-hole.  If so replace with an original and install new in .d directory
version_check_dnsmasq() {
    # Local, named variables
    local dnsmasq_conf="/etc/dnsmasq.conf"
    local dnsmasq_conf_orig="/etc/dnsmasq.conf.orig"
    local dnsmasq_pihole_id_string="addn-hosts=/etc/pihole/gravity.list"
    local dnsmasq_pihole_id_string2="# Dnsmasq config for Pi-hole's FTLDNS"
    local dnsmasq_original_config="${PWD}/${LOCAL_PI_HOLE}/advanced/dnsmasq.conf.original"
    local dnsmasq_pihole_01_source="${PWD}/${LOCAL_PI_HOLE}/advanced/01-pihole.conf"
    local dnsmasq_pihole_01_target="/etc/dnsmasq.d/01-pihole.conf"
    local dnsmasq_rfc6761_06_source="${PWD}/${LOCAL_PI_HOLE}/advanced/06-rfc6761.conf"
    local dnsmasq_rfc6761_06_target="/etc/dnsmasq.d/06-rfc6761.conf"

    # If the dnsmasq config file exists
    if [[ -f "${dnsmasq_conf}" ]]; then
        printf "  %b Existing dnsmasq.conf found..." "${INFO}"
        # If a specific string is found within this file, we presume it's from older versions on Pi-hole,
        if grep -q "${dnsmasq_pihole_id_string}" "${dnsmasq_conf}" ||
           grep -q "${dnsmasq_pihole_id_string2}" "${dnsmasq_conf}"; then
            printf " it is from a previous Pi-hole install.\\n"
            printf "  %b Backing up dnsmasq.conf to dnsmasq.conf.orig..." "${INFO}"
            # so backup the original file,
            mv -f "${dnsmasq_conf}" "${dnsmasq_conf_orig}"
            printf "%b  %b Backing up dnsmasq.conf to dnsmasq.conf.orig...\\n" "${OVER}"  "${TICK}"
            printf "  %b Restoring default dnsmasq.conf..." "${INFO}"
            # and replace it with the default
            install -D -m 644 -T "${dnsmasq_original_config}" "${dnsmasq_conf}"
            printf "%b  %b Restoring default dnsmasq.conf...\\n" "${OVER}"  "${TICK}"
        else
            # Otherwise, don't to anything
            printf " it is not a Pi-hole file, leaving alone!\\n"
        fi
    else
        # If a file cannot be found,
        printf "  %b No dnsmasq.conf found... restoring default dnsmasq.conf..." "${INFO}"
        # restore the default one
        install -D -m 644 -T "${dnsmasq_original_config}" "${dnsmasq_conf}"
        printf "%b  %b No dnsmasq.conf found... restoring default dnsmasq.conf...\\n" "${OVER}"  "${TICK}"
    fi

    printf "  %b Installing %s..." "${INFO}" "${dnsmasq_pihole_01_target}"
    # Check to see if dnsmasq directory exists (it may not due to being a fresh install and dnsmasq no longer being a dependency)
    if [[ ! -d "/etc/dnsmasq.d"  ]];then
        install -d -m 755 "/etc/dnsmasq.d"
    fi
    # Copy the new Pi-hole DNS config file into the dnsmasq.d directory
    install -D -m 644 -T "${dnsmasq_pihole_01_source}" "${dnsmasq_pihole_01_target}"
    printf "%b  %b Installed %s\n" "${OVER}"  "${TICK}" "${dnsmasq_pihole_01_target}"
    # Replace our placeholder values with the GLOBAL DNS variables that we populated earlier
    # First, swap in the interface to listen on,
    sed -i "s/@INT@/$PIHOLE_INTERFACE/" "${dnsmasq_pihole_01_target}"
    if [[ "${PIHOLE_DNS_1}" != "" ]]; then
        # then swap in the primary DNS server.
        sed -i "s/@DNS1@/$PIHOLE_DNS_1/" "${dnsmasq_pihole_01_target}"
    else
        # Otherwise, remove the line which sets DNS1.
        sed -i '/^server=@DNS1@/d' "${dnsmasq_pihole_01_target}"
    fi
    # Ditto if DNS2 is not empty
    if [[ "${PIHOLE_DNS_2}" != "" ]]; then
        sed -i "s/@DNS2@/$PIHOLE_DNS_2/" "${dnsmasq_pihole_01_target}"
    else
        sed -i '/^server=@DNS2@/d' "${dnsmasq_pihole_01_target}"
    fi

    # Set the cache size
    sed -i "s/@CACHE_SIZE@/$CACHE_SIZE/" "${dnsmasq_pihole_01_target}"

    sed -i 's/^#conf-dir=\/etc\/dnsmasq.d$/conf-dir=\/etc\/dnsmasq.d/' "${dnsmasq_conf}"

    # If the user does not want to enable logging,
    if [[ "${QUERY_LOGGING}" == false ]] ; then
        # disable it by commenting out the directive in the DNS config file
        sed -i 's/^log-queries/#log-queries/' "${dnsmasq_pihole_01_target}"
    else
        # Otherwise, enable it by uncommenting the directive in the DNS config file
        sed -i 's/^#log-queries/log-queries/' "${dnsmasq_pihole_01_target}"
    fi

    printf "  %b Installing %s..." "${INFO}" "${dnsmasq_rfc6761_06_source}"
    install -D -m 644 -T "${dnsmasq_rfc6761_06_source}" "${dnsmasq_rfc6761_06_target}"
    printf "%b  %b Installed %s\n" "${OVER}"  "${TICK}" "${dnsmasq_rfc6761_06_target}"
}

# Install the scripts from repository to their various locations
installScripts() {
    # Local, named variables
    local str="Installing scripts from ${PWD}"
    printf "  %b %s..." "${INFO}" "${str}"

    install -o "${USER}" -Dm755 -d "${PI_HOLE_INSTALL_DIR}"

    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" pi-hole-5.11.4/gravity.sh
    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" pi-hole-5.11.4/advanced/Templates/*.sql
    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" pi-hole-5.11.4/advanced/Scripts/database_migration/*.sh
    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" pi-hole-5.11.4/advanced/Scripts/database_migration/gravity/*.sql
    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" pi-hole-5.11.4/advanced/Scripts/*.sh
    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" pi-hole-5.11.4/automated\ install/uninstall.sh
    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" local-install.sh
    install -o "${USER}" -Dm755 -t "${PI_HOLE_INSTALL_DIR}" pi-hole-5.11.4/advanced/Scripts/COL_TABLE
    install -o "${USER}" -Dm755 -t "${PI_HOLE_BIN_DIR}" pi-hole-5.11.4/pihole
    install -Dm644 pi-hole-5.11.4/advanced/bash-completion/pihole /etc/bash_completion.d/pihole
    printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
}

# Install the configs from PI_HOLE_LOCAL_REPO to their various locations
installConfigs() {
    printf "\\n  %b Installing configs from %s...\\n" "${INFO}" "${PWD}/${LOCAL_PI_HOLE}"
    # Make sure Pi-hole's config files are in place
    version_check_dnsmasq

    # Install list of DNS servers
    # Format: Name;Primary IPv4;Secondary IPv4;Primary IPv6;Secondary IPv6
    # Some values may be empty (for example: DNS servers without IPv6 support)
    echo "${DNS_SERVERS}" > "${PI_HOLE_CONFIG_DIR}/dns-servers.conf"
    chmod 644 "${PI_HOLE_CONFIG_DIR}/dns-servers.conf"

    # Install template file if it does not exist
    if [[ ! -r "${PI_HOLE_CONFIG_DIR}/pihole-FTL.conf" ]]; then
        install -d -m 0755 ${PI_HOLE_CONFIG_DIR}
        if ! install -T -o pihole -m 664 "${PWD}/${LOCAL_PI_HOLE}/advanced/Templates/pihole-FTL.conf" "${PI_HOLE_CONFIG_DIR}/pihole-FTL.conf" &>/dev/null; then
            printf "  %b Error: Unable to initialize configuration file %s/pihole-FTL.conf\\n" "${COL_LIGHT_RED}" "${PI_HOLE_CONFIG_DIR}"
            return 1
        fi
    fi

    # Install empty custom.list file if it does not exist
    if [[ ! -r "${PI_HOLE_CONFIG_DIR}/custom.list" ]]; then
        if ! install -o root -m 644 /dev/null "${PI_HOLE_CONFIG_DIR}/custom.list" &>/dev/null; then
            printf "  %b Error: Unable to initialize configuration file %s/custom.list\\n" "${COL_LIGHT_RED}" "${PI_HOLE_CONFIG_DIR}"
            return 1
        fi
    fi

    # Install pihole-FTL.service
    install -T -m 0755 "${PWD}/${LOCAL_PI_HOLE}/advanced/Templates/pihole-FTL.service" "/etc/init.d/pihole-FTL"

    # If the user chose to install the dashboard,
    if [[ "${INSTALL_WEB_SERVER}" == true ]]; then
        # and if the Web server conf directory does not exist,
        if [[ ! -d "/etc/lighttpd" ]]; then
            # make it and set the owners
            install -d -m 755 -o "${USER}" -g root /etc/lighttpd
        # Otherwise, if the config file already exists
        elif [[ -f "${lighttpdConfig}" ]]; then
            # back up the original
            mv "${lighttpdConfig}"{,.orig}
        fi
        # and copy in the config file Pi-hole needs
        install -D -m 644 -T ${PWD}/${LOCAL_PI_HOLE}/advanced/${LIGHTTPD_CFG} "${lighttpdConfig}"
        # Make sure the external.conf file exists, as lighttpd v1.4.50 crashes without it
        if [ ! -f /etc/lighttpd/external.conf ]; then
            install -m 644 /dev/null /etc/lighttpd/external.conf
        fi
        # If there is a custom block page in the html/pihole directory, replace 404 handler in lighttpd config
        if [[ -f "${PI_HOLE_BLOCKPAGE_DIR}/custom.php" ]]; then
            sed -i 's/^\(server\.error-handler-404\s*=\s*\).*$/\1"\/pihole\/custom\.php"/' "${lighttpdConfig}"
        fi
        # Make the directories if they do not exist and set the owners
        mkdir -p /run/lighttpd
        chown ${LIGHTTPD_USER}:${LIGHTTPD_GROUP} /run/lighttpd
        mkdir -p /var/cache/lighttpd/compress
        chown ${LIGHTTPD_USER}:${LIGHTTPD_GROUP} /var/cache/lighttpd/compress
        mkdir -p /var/cache/lighttpd/uploads
        chown ${LIGHTTPD_USER}:${LIGHTTPD_GROUP} /var/cache/lighttpd/uploads
    fi
}

install_manpage() {
    # Copy Pi-hole man pages and call mandb to update man page database
    # Default location for man files for /usr/local/bin is /usr/local/share/man
    # on lightweight systems may not be present, so check before copying.
    printf "  %b Testing man page installation" "${INFO}"
    if ! is_command mandb ; then
        # if mandb is not present, no manpage support
        printf "%b  %b man not installed\\n" "${OVER}" "${INFO}"
        return
    elif [[ ! -d "/usr/local/share/man" ]]; then
        # appropriate directory for Pi-hole's man page is not present
        printf "%b  %b man pages not installed\\n" "${OVER}" "${INFO}"
        return
    fi
    if [[ ! -d "/usr/local/share/man/man8" ]]; then
        # if not present, create man8 directory
        install -d -m 755 /usr/local/share/man/man8
    fi
    if [[ ! -d "/usr/local/share/man/man5" ]]; then
        # if not present, create man5 directory
        install -d -m 755 /usr/local/share/man/man5
    fi
    # Testing complete, copy the files & update the man db
    install -D -m 644 -T ${PWD}/${LOCAL_PI_HOLE}/manpages/pihole.8 /usr/local/share/man/man8/pihole.8
    install -D -m 644 -T ${PWD}/${LOCAL_PI_HOLE}/manpages/pihole-FTL.8 /usr/local/share/man/man8/pihole-FTL.8

    # remove previously installed "pihole-FTL.conf.5" man page
    if [[ -f "/usr/local/share/man/man5/pihole-FTL.conf.5" ]]; then
        rm /usr/local/share/man/man5/pihole-FTL.conf.5
    fi

    if mandb -q &>/dev/null; then
        # Updated successfully
        printf "%b  %b man pages installed and database updated\\n" "${OVER}" "${TICK}"
        return
    else
        # Something is wrong with the system's man installation, clean up
        # our files, (leave everything how we found it).
        rm /usr/local/share/man/man8/pihole.8 /usr/local/share/man/man8/pihole-FTL.8
        printf "%b  %b man page db not updated, man pages not installed\\n" "${OVER}" "${CROSS}"
    fi
}

stop_service() {
    # Stop service passed in as argument.
    # Can softfail, as process may not be installed when this is called
    local str="Stopping ${1} service"
    printf "  %b %s..." "${INFO}" "${str}"
    if is_command systemctl ; then
        systemctl stop "${1}" &> /dev/null || true
    else
        service "${1}" stop &> /dev/null || true
    fi
    printf "%b  %b %s...\\n" "${OVER}" "${TICK}" "${str}"
}

# Start/Restart service passed in as argument
restart_service() {
    # Local, named variables
    local str="Restarting ${1} service"
    printf "  %b %s..." "${INFO}" "${str}"
    service "${1}" restart
    printf "%b  %b %s...\\n" "${OVER}" "${TICK}" "${str}"
}

check_service_active() {
    # If systemctl exists,
    if is_command systemctl ; then
        # use that to check the status of the service
        systemctl is-enabled "${1}" &> /dev/null
    else
        # Otherwise, fall back to service command
        service "${1}" status &> /dev/null
    fi
}

# Systemd-resolved's DNSStubListener and dnsmasq can't share port 53.
disable_resolved_stublistener() {
    printf "  %b Testing if systemd-resolved is enabled\\n" "${INFO}"
    # Check if Systemd-resolved's DNSStubListener is enabled and active on port 53
    if check_service_active "systemd-resolved"; then
        # Check if DNSStubListener is enabled
        printf "  %b %b Testing if systemd-resolved DNSStub-Listener is active" "${OVER}" "${INFO}"
        if ( grep -E '#?DNSStubListener=yes' /etc/systemd/resolved.conf &> /dev/null ); then
            # Disable the DNSStubListener to unbind it from port 53
            # Note that this breaks dns functionality on host until dnsmasq/ftl are up and running
            printf "%b  %b Disabling systemd-resolved DNSStubListener" "${OVER}" "${TICK}"
            # Make a backup of the original /etc/systemd/resolved.conf
            # (This will need to be restored on uninstallation)
            sed -r -i.orig 's/#?DNSStubListener=yes/DNSStubListener=no/g' /etc/systemd/resolved.conf
            printf " and restarting systemd-resolved\\n"
            systemctl reload-or-restart systemd-resolved
        else
            printf "%b  %b Systemd-resolved does not need to be restarted\\n" "${OVER}" "${INFO}"
        fi
    else
        printf "%b  %b Systemd-resolved is not enabled\\n" "${OVER}" "${INFO}"
    fi
}

update_package_cache() {
    # Update package cache on apt based OSes. Do this every time since
    # it's quick and packages can be updated at any time.

    # Local, named variables
    local str="Update local cache of available packages"
    printf "  %b %s..." "${INFO}" "${str}"
    # Create a command from the package cache variable
    if eval "${UPDATE_PKG_CACHE}" &> /dev/null; then
        printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
    else
        # Otherwise, show an error and exit

        # In case we used apt-get and apt is also available, we use this as recommendation as we have seen it
        # gives more user-friendly (interactive) advice
        if [[ ${PKG_MANAGER} == "apt-get" ]] && is_command apt ; then
            UPDATE_PKG_CACHE="apt update"
        fi
        printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
        printf "  %b Error: Unable to update package cache. Please try \"%s\"%b\\n" "${COL_LIGHT_RED}" "sudo ${UPDATE_PKG_CACHE}" "${COL_NC}"
        return 1
    fi
}

# Let user know if they have outdated packages on their system and
# advise them to run a package update at soonest possible.
notify_package_updates_available() {
    # Local, named variables
    local str="Checking ${PKG_MANAGER} for upgraded packages"
    printf "\\n  %b %s..." "${INFO}" "${str}"
    # Store the list of packages in a variable
    updatesToInstall=$(eval "${PKG_COUNT}")

    if [[ -d "/lib/modules/$(uname -r)" ]]; then
        if [[ "${updatesToInstall}" -eq 0 ]]; then
            printf "%b  %b %s... up to date!\\n\\n" "${OVER}" "${TICK}" "${str}"
        else
            printf "%b  %b %s... %s updates available\\n" "${OVER}" "${TICK}" "${str}" "${updatesToInstall}"
            printf "  %b %bIt is recommended to update your OS after installing the Pi-hole!%b\\n\\n" "${INFO}" "${COL_LIGHT_GREEN}" "${COL_NC}"
        fi
    else
        printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
        printf "      Kernel update detected. If the install fails, please reboot and try again\\n"
    fi
}

install_dependent_packages() {

    # Install packages passed in via argument array
    # No spinner - conflicts with set -e
    declare -a installArray

    # Debian based package install - debconf will download the entire package list
    # so we just create an array of packages not currently installed to cut down on the
    # amount of download traffic.
    # NOTE: We may be able to use this installArray in the future to create a list of package that were
    # installed by us, and remove only the installed packages, and not the entire list.
    if is_command apt-get ; then
        # For each package, check if it's already installed (and if so, don't add it to the installArray)
        for i in "$@"; do
            printf "  %b Checking for %s..." "${INFO}" "${i}"
            if dpkg-query -W -f='${Status}' "${i}" 2>/dev/null | grep "ok installed" &> /dev/null; then
                printf "%b  %b Checking for %s\\n" "${OVER}" "${TICK}" "${i}"
            else
                printf "%b  %b Checking for %s (will be installed)\\n" "${OVER}" "${INFO}" "${i}"
                installArray+=("${i}")
            fi
        done
        # If there's anything to install, install everything in the list.
        if [[ "${#installArray[@]}" -gt 0 ]]; then
            test_dpkg_lock
            # Running apt-get install with minimal output can cause some issues with
            # requiring user input (e.g password for phpmyadmin see #218)
            printf "  %b Processing %s install(s) for: %s, please wait...\\n" "${INFO}" "${PKG_MANAGER}" "${installArray[*]}"
            printf '%*s\n' "$columns" '' | tr " " -;
            "${PKG_INSTALL[@]}" "${installArray[@]}"
            printf '%*s\n' "$columns" '' | tr " " -;
            return
        fi
        printf "\\n"
        return 0
    fi

    # Install Fedora/CentOS packages
    for i in "$@"; do
        # For each package, check if it's already installed (and if so, don't add it to the installArray)
        printf "  %b Checking for %s..." "${INFO}" "${i}"
        if "${PKG_MANAGER}" -q list installed "${i}" &> /dev/null; then
            printf "%b  %b Checking for %s\\n" "${OVER}" "${TICK}" "${i}"
        else
            printf "%b  %b Checking for %s (will be installed)\\n" "${OVER}" "${INFO}" "${i}"
            installArray+=("${i}")
        fi
    done
    # If there's anything to install, install everything in the list.
    if [[ "${#installArray[@]}" -gt 0 ]]; then
        printf "  %b Processing %s install(s) for: %s, please wait...\\n" "${INFO}" "${PKG_MANAGER}" "${installArray[*]}"
        printf '%*s\n' "$columns" '' | tr " " -;
        "${PKG_INSTALL[@]}" "${installArray[@]}"
        printf '%*s\n' "$columns" '' | tr " " -;
        return
    fi
    printf "\\n"
    return 0
}

# Install the Web interface dashboard
installPiholeWeb() {
    printf "\\n  %b Installing blocking page...\\n" "${INFO}"

    local str="Creating directory for blocking page, and copying files"
    printf "  %b %s..." "${INFO}" "${str}"
    # Install the directory,
    install -d -m 0755 ${PI_HOLE_BLOCKPAGE_DIR}
    # and the blockpage
    install -D -m 644 ${PWD}/${LOCAL_PI_HOLE}/advanced/{index,blockingpage}.* ${PI_HOLE_BLOCKPAGE_DIR}/

    # Remove superseded file
    if [[ -e "${PI_HOLE_BLOCKPAGE_DIR}/index.js" ]]; then
        rm "${PI_HOLE_BLOCKPAGE_DIR}/index.js"
    fi

    printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"

    local str="Backing up index.lighttpd.html"
    printf "  %b %s..." "${INFO}" "${str}"
    # If the default index file exists,
    if [[ -f "${webroot}/index.lighttpd.html" ]]; then
        # back it up
        mv ${webroot}/index.lighttpd.html ${webroot}/index.lighttpd.orig
        printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
    else
        # Otherwise, don't do anything
        printf "%b  %b %s\\n" "${OVER}" "${INFO}" "${str}"
        printf "      No default index.lighttpd.html file found... not backing up\\n"
    fi

    # Install Sudoers file
    local str="Installing sudoer file"
    printf "\\n  %b %s..." "${INFO}" "${str}"
    # Make the .d directory if it doesn't exist,
    install -d -m 755 /etc/sudoers.d/
    # and copy in the pihole sudoers file
    install -m 0640 ${PWD}/${LOCAL_PI_HOLE}/advanced/Templates/pihole.sudo /etc/sudoers.d/pihole
    # Add lighttpd user (OS dependent) to sudoers file
    echo "${LIGHTTPD_USER} ALL=NOPASSWD: ${PI_HOLE_BIN_DIR}/pihole" >> /etc/sudoers.d/pihole

    # If the Web server user is lighttpd,
    if [[ "$LIGHTTPD_USER" == "lighttpd" ]]; then
        # Allow executing pihole via sudo with Fedora
        # Usually /usr/local/bin ${PI_HOLE_BIN_DIR} is not permitted as directory for sudoable programs
        echo "Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin:${PI_HOLE_BIN_DIR}" >> /etc/sudoers.d/pihole
    fi
    # Set the strict permissions on the file
    chmod 0440 /etc/sudoers.d/pihole
    printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
}

# Installs a cron file
installCron() {
    # Install the cron job
    local str="Installing latest Cron script"
    printf "\\n  %b %s..." "${INFO}" "${str}"
    # Copy the cron file over from the local repo
    # File must not be world or group writeable and must be owned by root
    install -D -m 644 -T -o root -g root ${PWD}/${LOCAL_PI_HOLE}/advanced/Templates/pihole.cron /etc/cron.d/pihole
    # Randomize gravity update time
    sed -i "s/59 1 /$((1 + RANDOM % 58)) $((3 + RANDOM % 2))/" /etc/cron.d/pihole
    # Randomize update checker time
    sed -i "s/59 17/$((1 + RANDOM % 58)) $((12 + RANDOM % 8))/" /etc/cron.d/pihole
    printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
}

# Gravity is a very important script as it aggregates all of the domains into a single HOSTS formatted list,
# which is what Pi-hole needs to begin blocking ads
runGravity() {
    # Run gravity in the current shell
    printf "Run gravity.sh"
    sudo $PI_HOLE_INSTALL_DIR/gravity.sh --force;
}

# Check if the pihole user exists and create if it does not
create_pihole_user() {
    local str="Checking for user 'pihole'"
    printf "  %b %s..." "${INFO}" "${str}"
    # If the pihole user exists,
    if id -u pihole &> /dev/null; then
        # and if the pihole group exists,
        if getent group pihole > /dev/null 2>&1; then
            # succeed
            printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
        else
            local str="Checking for group 'pihole'"
            printf "  %b %s..." "${INFO}" "${str}"
            local str="Creating group 'pihole'"
            # if group can be created
            if groupadd pihole; then
                printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
                local str="Adding user 'pihole' to group 'pihole'"
                printf "  %b %s..." "${INFO}" "${str}"
                # if pihole user can be added to group pihole
                if usermod -g pihole pihole; then
                    printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
                else
                    printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
                fi
            else
                printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
            fi
        fi
    else
        # If the pihole user doesn't exist,
        printf "%b  %b %s" "${OVER}" "${CROSS}" "${str}"
        local str="Creating user 'pihole'"
        printf "%b  %b %s..." "${OVER}" "${INFO}" "${str}"
        # create her with the useradd command,
        if getent group pihole > /dev/null 2>&1; then
            # then add her to the pihole group (as it already exists)
            if useradd -r --no-user-group -g pihole -s /usr/sbin/nologin pihole; then
                printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
            else
                printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
            fi
        else
            # add user pihole with default group settings
            if useradd -r -s /usr/sbin/nologin pihole; then
                printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
            else
                printf "%b  %b %s\\n" "${OVER}" "${CROSS}" "${str}"
            fi
        fi
    fi
}

# This function saves any changes to the setup variables into the setupvars.conf file for future runs
finalExports() {
    # If the setup variable file exists,
    if [[ -e "${setupVars}" ]]; then
        # update the variables in the file
        sed -i.update.bak '/PIHOLE_INTERFACE/d;/PIHOLE_DNS_1\b/d;/PIHOLE_DNS_2\b/d;/QUERY_LOGGING/d;/INSTALL_WEB_SERVER/d;/INSTALL_WEB_INTERFACE/d;/LIGHTTPD_ENABLED/d;/CACHE_SIZE/d;/DNS_FQDN_REQUIRED/d;/DNS_BOGUS_PRIV/d;/DNSMASQ_LISTENING/d;' "${setupVars}"
    fi
    # echo the information to the user
    {
        echo "PIHOLE_INTERFACE=${PIHOLE_INTERFACE}"
        echo "PIHOLE_DNS_1=${PIHOLE_DNS_1}"
        echo "PIHOLE_DNS_2=${PIHOLE_DNS_2}"
        echo "PIHOLE_DNS_3=${PIHOLE_DNS_3}"
        echo "PIHOLE_DNS_4=${PIHOLE_DNS_4}"
        echo "QUERY_LOGGING=${QUERY_LOGGING}"
        echo "INSTALL_WEB_SERVER=${INSTALL_WEB_SERVER}"
        echo "INSTALL_WEB_INTERFACE=${INSTALL_WEB_INTERFACE}"
        echo "LIGHTTPD_ENABLED=${LIGHTTPD_ENABLED}"
        echo "CACHE_SIZE=${CACHE_SIZE}"
        echo "DNS_FQDN_REQUIRED=${DNS_FQDN_REQUIRED:-false}"
        echo "DNS_BOGUS_PRIV=${DNS_BOGUS_PRIV:-false}"
        echo "DNSMASQ_LISTENING=${DNSMASQ_LISTENING:-bind}"
    }>> "${setupVars}"
    chmod 644 "${setupVars}"

    # Set the privacy level
    sed -i '/PRIVACYLEVEL/d' "${PI_HOLE_CONFIG_DIR}/pihole-FTL.conf"
    echo "PRIVACYLEVEL=${PRIVACY_LEVEL}" >> "${PI_HOLE_CONFIG_DIR}/pihole-FTL.conf"

    # Bring in the current settings and the functions to manipulate them
    source "${setupVars}"
    source "${PWD}/${LOCAL_PI_HOLE}/advanced/Scripts/webpage.sh"

    # Look for DNS server settings which would have to be reapplied
    ProcessDNSSettings

    # Look for DHCP server settings which would have to be reapplied
    ProcessDHCPSettings
}

# Install the logrotate script
installLogrotate() {
    local str="Installing latest logrotate script"
    local target=/etc/pihole/logrotate

    printf "\\n  %b %s..." "${INFO}" "${str}"
    if [[ -f ${target} ]]; then

        # Account for changed logfile paths from /var/log -> /var/log/pihole/ made in core v5.11.
        if  grep -q "/var/log/pihole.log" ${target}  ||  grep -q "/var/log/pihole-FTL.log" ${target}; then
            sed -i 's/\/var\/log\/pihole.log/\/var\/log\/pihole\/pihole.log/g' ${target}
            sed -i 's/\/var\/log\/pihole-FTL.log/\/var\/log\/pihole\/FTL.log/g' ${target}

            printf "\\n\\t%b Old log file paths updated in existing logrotate file. \\n" "${INFO}"
            return 3
        fi

        printf "\\n\\t%b Existing logrotate file found. No changes made.\\n" "${INFO}"
        # Return value isn't that important, using 2 to indicate that it's not a fatal error but
        # the function did not complete.
        return 2
    fi
    # Copy the file over from the local repo
    install -D -m 644 -T "${PWD}/${LOCAL_PI_HOLE}"/advanced/Templates/logrotate ${target}
    # Different operating systems have different user / group
    # settings for logrotate that makes it impossible to create
    # a static logrotate file that will work with e.g.
    # Rasbian and Ubuntu at the same time. Hence, we have to
    # customize the logrotate script here in order to reflect
    # the local properties of the /var/log directory
    logusergroup="$(stat -c '%U %G' /var/log)"
    # If there is a usergroup for log rotation,
    if [[ -n "${logusergroup}" ]]; then
        # replace the line in the logrotate script with that usergroup.
        sed -i "s/# su #/su ${logusergroup}/g;" ${target}
    fi
    printf "%b  %b %s\\n" "${OVER}" "${TICK}" "${str}"
}

# Install base files and web interface
installPihole() {
    # If the user wants to install the Web interface,
    if [[ "${INSTALL_WEB_INTERFACE}" == true ]]; then
        if [[ ! -d "${webroot}" ]]; then
            # make the Web directory if necessary
            install -d -m 0755 /var/www
            install -d -m 0755 ${webroot}
        fi

        if [[ "${INSTALL_WEB_SERVER}" == true ]]; then
            # Set the owner and permissions
            chown ${LIGHTTPD_USER}:${LIGHTTPD_GROUP} ${webroot}
            chmod 0775 ${webroot}
            # Repair permissions if webroot is not world readable
            chmod a+rx /var/www
            chmod a+rx ${webroot}
            # Give lighttpd access to the pihole group so the web interface can
            # manage the gravity.db database
            usermod -a -G pihole ${LIGHTTPD_USER}
            # If the lighttpd command is executable,
            if is_command lighty-enable-mod ; then
                # enable fastcgi and fastcgi-php
                lighty-enable-mod fastcgi fastcgi-php > /dev/null || true
            else
                # Otherwise, show info about installing them
                printf "  %b Warning: 'lighty-enable-mod' utility not found\\n" "${INFO}"
                printf "      Please ensure fastcgi is enabled if you experience issues\\n"
            fi
        fi
    fi
    # Install base files and web interface
    if ! installScripts; then
        printf "  %b Failure in dependent script copy function.\\n" "${CROSS}"
        exit 1
    fi
    # Install config files
    if ! installConfigs; then
        printf "  %b Failure in dependent config copy function.\\n" "${CROSS}"
        exit 1
    fi
    # If the user wants to install the dashboard,
    if [[ "${INSTALL_WEB_INTERFACE}" == true ]]; then
        # do so
        installPiholeWeb
    fi
    # Install the cron file
    installCron

    # # Install the logrotate file
    installLogrotate || true

    # # install a man page entry for pihole
    install_manpage

    # # Update setupvars.conf with any variables that may or may not have been changed during the install
    finalExports
}

# SELinux
checkSelinux() {
    local DEFAULT_SELINUX
    local CURRENT_SELINUX
    local SELINUX_ENFORCING=0
    # Check for SELinux configuration file and getenforce command
    if [[ -f /etc/selinux/config ]] && is_command getenforce; then
        # Check the default SELinux mode
        DEFAULT_SELINUX=$(awk -F= '/^SELINUX=/ {print $2}' /etc/selinux/config)
        case "${DEFAULT_SELINUX,,}" in
            enforcing)
                printf "  %b %bDefault SELinux: %s%b\\n" "${CROSS}" "${COL_RED}" "${DEFAULT_SELINUX,,}" "${COL_NC}"
                SELINUX_ENFORCING=1
                ;;
            *)  # 'permissive' and 'disabled'
                printf "  %b %bDefault SELinux: %s%b\\n" "${TICK}" "${COL_GREEN}" "${DEFAULT_SELINUX,,}" "${COL_NC}"
                ;;
        esac
        # Check the current state of SELinux
        CURRENT_SELINUX=$(getenforce)
        case "${CURRENT_SELINUX,,}" in
            enforcing)
                printf "  %b %bCurrent SELinux: %s%b\\n" "${CROSS}" "${COL_RED}" "${CURRENT_SELINUX,,}" "${COL_NC}"
                SELINUX_ENFORCING=1
                ;;
            *)  # 'permissive' and 'disabled'
                printf "  %b %bCurrent SELinux: %s%b\\n" "${TICK}" "${COL_GREEN}" "${CURRENT_SELINUX,,}" "${COL_NC}"
                ;;
        esac
    else
        echo -e "  ${INFO} ${COL_GREEN}SELinux not detected${COL_NC}";
    fi
    # Exit the installer if any SELinux checks toggled the flag
    if [[ "${SELINUX_ENFORCING}" -eq 1 ]] && [[ -z "${PIHOLE_SELINUX}" ]]; then
        printf "  Pi-hole does not provide an SELinux policy as the required changes modify the security of your system.\\n"
        printf "  Please refer to https://wiki.centos.org/HowTos/SELinux if SELinux is required for your deployment.\\n"
        printf "      This check can be skipped by setting the environment variable %bPIHOLE_SELINUX%b to %btrue%b\\n" "${COL_LIGHT_RED}" "${COL_NC}" "${COL_LIGHT_RED}" "${COL_NC}"
        printf "      e.g: export PIHOLE_SELINUX=true\\n"
        printf "      By setting this variable to true you acknowledge there may be issues with Pi-hole during or after the install\\n"
        printf "\\n  %bSELinux Enforcing detected, exiting installer%b\\n" "${COL_LIGHT_RED}" "${COL_NC}";
        exit 1;
    elif [[ "${SELINUX_ENFORCING}" -eq 1 ]] && [[ -n "${PIHOLE_SELINUX}" ]]; then
        printf "  %b %bSELinux Enforcing detected%b. PIHOLE_SELINUX env variable set - installer will continue\\n" "${INFO}" "${COL_LIGHT_RED}" "${COL_NC}"
    fi
}

FTLinstallLocal() {
    local str="Using local FTL binary"
    printf " %b %s..." "${INFO}" "${str}"

    if [[ ! -f "${LOCAL_FTL}" ]]; then
        printf "%b %b %s\\n" "${OVER}" "${CROSS}" "${str}"
        printf " %b Local FTL binary not found at: %s\\n" "${CROSS}" "${LOCAL_FTL}"
        return 1
    fi

    install -T -m 0755 "${LOCAL_FTL}" "/usr/bin/pihole-FTL"

    printf "%b %b %s\\n" "${OVER}" "${TICK}" "${str}"
    return 0
}

WEBinstallLocal() {
    cp -r ${LOCAL_WEB} ${webInterfaceDir}
}

make_temporary_log() {
    # Create a random temporary file for the log
    TEMPLOG=$(mktemp /tmp/pihole_temp.XXXXXX)
    # Open handle 3 for templog
    # https://stackoverflow.com/questions/18460186/writing-outputs-to-log-file-and-console
    exec 3>"$TEMPLOG"
    # Delete templog, but allow for addressing via file handle
    # This lets us write to the log without having a temporary file on the drive, which
    # is meant to be a security measure so there is not a lingering file on the drive during the install process
    rm "$TEMPLOG"
}

copy_to_install_log() {
    # Copy the contents of file descriptor 3 into the install log
    # Since we use color codes such as '\e[1;33m', they should be removed
    sed 's/\[[0-9;]\{1,5\}m//g' < /proc/$$/fd/3 > "${installLogLoc}"
    chmod 644 "${installLogLoc}"
}

main() {
    ######## FIRST CHECK ########
    # Must be root to install
    local str="Root user check"
    printf "\\n"

    # If the user's id is zero,
    if [[ "${EUID}" -eq 0 ]]; then
        # they are root and all is good
        printf "  %b %s\\n" "${TICK}" "${str}"
        # Show the Pi-hole logo so people know it's genuine since the logo and name are trademarked
        show_ascii_berry
        make_temporary_log
    else
        # Otherwise, they do not have enough privileges, so let the user know
        printf "  %b %s\\n" "${INFO}" "${str}"
        printf "  %b %bScript called with non-root privileges%b\\n" "${INFO}" "${COL_LIGHT_RED}" "${COL_NC}"
        printf "      The Pi-hole requires elevated privileges to install and run\\n"
        printf "      Please check the installer for any concerns regarding this requirement\\n"
        printf "      Make sure to download this script from a trusted source\\n\\n"
        printf "  %b Sudo utility check" "${INFO}"

        # If the sudo command exists, try rerunning as admin
        if is_command sudo ; then
            printf "%b  %b Sudo utility check\\n" "${OVER}"  "${TICK}"

            #!@
            # # when run via curl piping
            # if [[ "$0" == "bash" ]]; then
            #     # Download the install script and run it with admin rights
            #     exec curl -sSL https://raw.githubusercontent.com/pi-hole/pi-hole/master/automated%20install/basic-install.sh | sudo bash "$@"
            # else
            #     # when run via calling local bash script
            #     exec sudo bash "$0" "$@"
            # fi
            #!@
            exec sudo bash "$0" "$@"

            exit $?
        else
            # Otherwise, tell the user they need to run the script as root, and bail
            printf "%b  %b Sudo utility check\\n" "${OVER}" "${CROSS}"
            printf "  %b Sudo is needed for the Web Interface to run pihole commands\\n\\n" "${INFO}"
            printf "  %b %bPlease re-run this installer as root${COL_NC}\\n" "${INFO}" "${COL_LIGHT_RED}"
            exit 1
        fi
    fi

    # Check if SELinux is Enforcing and exit before doing anything else
    checkSelinux

    # # Check for supported package managers so that we may install dependencies
    package_manager_detect

    # # Notify user of package availability
    notify_package_updates_available

    # # Install packages necessary to perform os_check
    # printf "  %b Checking for / installing Required dependencies for OS Check...\\n" "${INFO}"
    install_dependent_packages "${OS_CHECK_DEPS[@]}"

    # # Install packages used by this installation script
    # printf "  %b Checking for / installing Required dependencies for this install script...\\n" "${INFO}"
    install_dependent_packages "${INSTALLER_DEPS[@]}"

    if [[ "${useUpdateVars}" == false ]]; then
        #!@
        # # Display welcome dialogs
        # welcomeDialogs
        #!@
        # Create directory for Pi-hole storage
        install -d -m 755 "$PI_HOLE_CONFIG_DIR"
        # Determine available interfaces
        get_available_interfaces
        # Find interfaces and let the user choose one
        chooseInterface
        # find IPv4 and IPv6 information of the device
        collect_v4andv6_information
        setDefaultBlocklist
    else
        # Setup adlist file if not exists
        installDefaultBlocklists

        # Source ${setupVars} to use predefined user variables in the functions
        source "${setupVars}"

        # Get the privacy level if it exists (default is 0)
        if [[ -f "${PI_HOLE_CONFIG_DIR}/pihole-FTL.conf" ]]; then
            PRIVACY_LEVEL=$(sed -ne 's/PRIVACYLEVEL=\(.*\)/\1/p' "${PI_HOLE_CONFIG_DIR}/pihole-FTL.conf")

            # If no setting was found, default to 0
            PRIVACY_LEVEL="${PRIVACY_LEVEL:-0}"
        fi
    fi

    # Install the Core dependencies
    local dep_install_list=("${PIHOLE_DEPS[@]}")
    if [[ "${INSTALL_WEB_SERVER}" == true ]]; then
        # And, if the setting says so, install the Web admin interface dependencies
        dep_install_list+=("${PIHOLE_WEB_DEPS[@]}")
    fi

    # Install packages used by the actual software
    printf "  %b Checking for / installing Required dependencies for Pi-hole software...\\n" "${INFO}"
    install_dependent_packages "${dep_install_list[@]}"
    unset dep_install_list

    # On some systems, lighttpd is not enabled on first install. We need to enable it here if the user
    # has chosen to install the web interface, else the LIGHTTPD_ENABLED check will fail
    # if [[ "${INSTALL_WEB_SERVER}" == true ]]; then
    #     enable_service lighttpd
    # fi
    # Determine if lighttpd is correctly enabled
    if check_service_active "lighttpd"; then
        LIGHTTPD_ENABLED=true
    else
        LIGHTTPD_ENABLED=false
    fi
    # Create the pihole user
    create_pihole_user

    # Install local FTL
    FTLinstallLocal

    # Install and log everything to a file
    installPihole | tee -a /proc/$$/fd/3

    WEBinstallLocal

    # Copy the temp log file into final log location for storage
    copy_to_install_log

    if [[ "${INSTALL_WEB_INTERFACE}" == true ]]; then
        echo "WEBPASSWORD=ee38988b248928f2cd8397cc1bf87f777b178585a9b8c9dac09ccdeefcb21bba" >> "${setupVars}"
    fi

    # Check for and disable systemd-resolved-DNSStubListener before reloading resolved
    # DNSStubListener needs to remain in place for installer to download needed files,
    # so this change needs to be made after installation is complete,
    # but before starting or resarting the dnsmasq or ftl services
    disable_resolved_stublistener

    # If the Web server was installed,
    if [[ "${INSTALL_WEB_SERVER}" == true ]]; then
        if [[ "${LIGHTTPD_ENABLED}" == true ]]; then
            restart_service lighttpd
        else
            printf "  %b Lighttpd is disabled, skipping service restart\\n" "${INFO}"
        fi
    fi

    printf "  %b Restarting services...\\n" "${INFO}"

    # Enable FTL
    # Ensure the service is enabled before trying to start it
    # Fixes a problem reported on Ubuntu 18.04 where trying to start
    # the service before enabling causes installer to exit
    # enable_service pihole-FTL

    # If this is an update from a previous Pi-hole installation
    # we need to move any existing `pihole*` logs from `/var/log` to `/var/log/pihole`
    # if /var/log/pihole.log is not a symlink (set during FTL startup) move the files
    # can be removed with Pi-hole v6.0
    # To be sure FTL is not running when we move the files we explicitly stop it here

    stop_service pihole-FTL &> /dev/null

    if [ ! -d /var/log/pihole/ ]; then
        mkdir -m 0755 /var/log/pihole/
    fi

    # Special handling for pihole-FTL.log -> pihole/FTL.log
    if [ -f /var/log/pihole-FTL.log ] && [ ! -L /var/log/pihole-FTL.log ]; then
        # /var/log/pihole-FTL.log      -> /var/log/pihole/FTL.log
        # /var/log/pihole-FTL.log.1    -> /var/log/pihole/FTL.log.1
        # /var/log/pihole-FTL.log.2.gz -> /var/log/pihole/FTL.log.2.gz
        # /var/log/pihole-FTL.log.3.gz -> /var/log/pihole/FTL.log.3.gz
        # /var/log/pihole-FTL.log.4.gz -> /var/log/pihole/FTL.log.4.gz
        # /var/log/pihole-FTL.log.5.gz -> /var/log/pihole/FTL.log.5.gz
        for f in /var/log/pihole-FTL.log*; do mv "$f" "$( sed "s/pihole-/pihole\//" <<< "$f")"; done
    fi

    # Remaining log files
    if [ -f /var/log/pihole.log ] && [ ! -L /var/log/pihole.log ]; then
        mv /var/log/pihole*.* /var/log/pihole/ 2>/dev/null
    fi

    # restart_service pihole-FTL

    # Download and compile the aggregated block list
    runGravity
}

# allow to source this script without running it
if [[ "${SKIP_INSTALL}" != true ]] ; then
    main "$@"
fi
