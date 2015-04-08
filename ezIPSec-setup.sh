#!/bin/bash
#
# CentOS 6 - IPSec Server EZ-Setup
#
# (C) 2014 bryanandrews.org
#

# assumed public interface
DEFAULT_PUBLICINTERFACE="eth0"
# assumed private interface
DEFAULT_PRIVATEINTERFACE="eth1"
# default PSK for IPSec traffic encryption
DEFAULT_PSK="gvw4gQsjs763gf#*RTF3qfw2aF*3gq72bq2@*%yf"
DEFAULT_PRIVATE_NETWORKS="%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12"
#
# SERVER SETTINGS
# this is a range of IP addresses given to users without static IPs set in /etc/ppp/chap-secrets on ipsec servers
DEFAULT_CLIENTRANGE="192.168.80.100-192.168.80.150"
DEFAULT_LOGIN="site2site-01"
DEFAULT_PASS="389fSGSSGdhh"
DEFAULT_IP="192.168.80.10" #static IP for this user, outside of the dynamic range above to theres no overlap
#
# CLIENT SETTINGS
# default destination server to connect the ipsec client to
DEFAULT_DEST="4.3.2.1"
DEFAULT_IPSECNAME="site1-to-site2"

echo
echo "This tool will assist in the setup of IPSec/L2TP tunnels on CentOS6 servers and OSPF for automatic private network routing in between VPN points for mesh or point to point networks."
echo "(C) 2014 BryanAndrews.org"
echo

show_menu(){
echo "
1) Install/Setup IPSec Server to this host
2) Install/Setup IPSec Tunnel from this host to an IPSec Server
3) Install/Setup OSPFd for automatic routing in the IPSec mesh network
4) Quit"
read opt
}



################################################################################################
#
#
function installIPSecClient() {

echo
echo "Setting this host up to connect to an IPSec server."
echo


read -e -p "IPSec Server to connect to: " -i $DEFAULT_DEST DEST
if [ -z $DEST ];then echo "ERROR: IPSec server can't be null."; exit 1; fi

read -e -p "IPSec/VPN Profile Name (No spaces): " -i $DEFAULT_IPSECNAME IPSECNAME
if [ -z $IPSECNAME ];then echo "ERROR: IPSec profile name shouldn't be null."; exit 1; fi
VPNTUNNELNAME=$IPSECNAME
if [[ $IPSECNAME = *[[:space:]]* ]];then
echo "ERROR: Profile name can not have spaces."
exit 1;
fi

read -e -p "IPSec Client Login (No spaces): " -i $DEFAULT_LOGIN LOGIN
if [ -z $LOGIN ];then echo "ERROR: Login shouldn't be null."; exit 1; fi

read -e -p "IPSec Client Password: " -i $DEFAULT_PASS PASS
if [ -z $PASS ];then echo "ERROR: Login password shouldn't be null."; exit 1; fi

read -e -p "Pre Shared Key (PSK): " -i $DEFAULT_PSK IKEPSK
if [ -z $IKEPSK ];then echo "ERROR: PSK shouldn't be null. That's stupid."; exit 1; fi

read -e -p "Public Interface: " -i $DEFAULT_PUBLICINTERFACE PUBLICINTERFACE
if [ ! -d /proc/sys/net/ipv4/conf/$PUBLICINTERFACE ];then echo "ERROR: device $PUBLICINTERFACE not found"; exit 1; fi

read -e -p "Private Interface: " -i $DEFAULT_PRIVATEINTERFACE PRIVATEINTERFACE
if [ ! -d /proc/sys/net/ipv4/conf/$PRIVATEINTERFACE ];then echo "ERROR: device $PRIVATEINTERFACE not found"; exit 1; fi
MEPRIV=$(ifconfig $PRIVATEINTERFACE| grep inet | head -n1 | awk '{print $2;}' | cut -d":" -f2)

read -e -p "Private Network masks behind the IPSec VPN: " -i $DEFAULT_PRIVATE_NETWORKS PRIVATE_NETWORKS
if [ -z $PRIVATE_NETWORKS ];then echo "ERROR: Private Networks list shouldn't be null."; exit 1; fi

setSysCTL

if [ -f /etc/init.d/ipsec ];then

	echo "Stopping exisitng ipsec and xl2tpd services..."
	/etc/init.d/ipsec stop
	/etc/init.d/xl2tpd stop

else

	if [ ! -f /etc/yum.repos.d/epel.repo ]; then
		echo "Installing EPEL repo..."
		yum -y install http://vesta.informatik.rwth-aachen.de/ftp/pub/Linux/fedora-epel/6/i386/epel-release-6-8.noarch.rpm > /dev/null
		if [ $? -ne 0 ];then echo "ERROR: EPEL repo install failed and this is required. Existing." exit 1; fi
	fi

	yum -y install xl2tpd openswan ppp lsof ppp policycoreutils >/dev/null
	if [ $? -ne 0 ];then echo "ERROR: installing required packages."; exit 1; fi

fi

if [ ! -f /etc/ipsec.conf ];then
#required header
echo > /etc/ipsec.conf
config setup
	virtual_private=$PRIVATE_NETWORKS
	nat_traversal=yes
	protostack=netkey
	oe=no
	# Replace eth0 with your network interface
	plutoopts="--interface=$PUBLICINTERFACE"
EOF
fi

grep "$IPSECNAME" /etc/ipsec.conf 2>&1 >/dev/null
if [ $? -ne 0 ];then
echo "
conn $IPSECNAME
	authby=secret
	pfs=no
	auto=start
	keyingtries=3
	dpddelay=30
	dpdtimeout=120
	dpdaction=clear
	rekey=yes
	ikelifetime=8h
	keylife=1h
	type=tunnel
	# Replace IP address with your local IP (private, behind NAT IP is okay as well)
	left=$MEPRIV
	leftnexthop=%defaultroute
	leftprotoport=17/1701
	# Replace IP address with your VPN servers IP
	right=$DEST
	rightprotoport=17/1701
" >> /etc/ipsec.conf
else
	echo "ERROR: connection profile for $IPSECNAME already defined in /etc/ipec.conf. Can't have duplicates."
	exit 1
fi

grep "$MEPRIV $DEST" /etc/ipsec.secrets >/dev/null
if [ $? -eq 0 ];then
	echo "WARNING: Found IPSec PSK for $MEPRIV to $DEST already in /etc/ipsec.secrets. Skipping Setup."
else
	echo "$MEPRIV $DEST : PSK \"${IKEPSK}\"" > /etc/ipsec.secrets
fi

grep "$VPNTUNNELNAME" /etc/xl2tpd/xl2tpd.conf >/dev/null
if [ $? -ne 0 ];then
cat >> "/etc/xl2tpd/xl2tpd.conf" <<EOF
[lac $VPNTUNNELNAME]
lns = $DEST
ppp debug = no
pppoptfile = /etc/ppp/options.l2tpd.$VPNTUNNELNAME
length bit = yes
redial = yes
redial timeout = 30
EOF
else
echo "WARNING: VPN profile for $VPNTUNNELNAME already found in /etc/xl2tpd/xl2tpd.conf. SKipping setup."
fi

cat > "/etc/ppp/options.l2tpd.$VPNTUNNELNAME" <<EOF
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-mschap-v2
noccp
noauth
idle 1800
mtu 1410
mru 1410
#this is important for remote sites not to pass all traffic
nodefaultroute
#usepeerdns
#debug
lock
connect-delay 5000
#this is the chap-secret login and password on the remote server
name $LOGIN
password $PASS
EOF
echo "Created /etc/ppp/options.l2tpd.$VPNTUNNELNAME client options config"

# old ipsec tool that will conflict if it exists
if [ -f /etc/init.d/racoon ];then
echo "WARNING: racoon install detected. Disabling and stopping racoon service."
chkconfig racoon off
/etc/init.d/racoon stop >/dev/null
fi

echo "Starting ipsec and xl2tpd now..."
chkconfig ipsec on
chkconfig xl2tpd on
service ipsec start
service xl2tpd start
ipsec auto --add $IPSECNAME

echo "Initiating the xl2tpd tunnel now..."
ipsec auto --up $IPSECNAME
echo "c $VPNTUNNELNAME" > /var/run/xl2tpd/l2tp-control

grep "$VPNTUNNELNAME" /etc/rc.local >/dev/null
if [ $? -ne 0 ];then
	echo "Adding IPSec/xl2tp tunnel start up rc.local..."
	echo "echo \"c $VPNTUNNELNAME\" > /var/run/xl2tpd/l2tp-control" >> /etc/rc.local
fi

}


################################################################################################
#
#
function setSysCTL() {

if [ $(cat /proc/sys/net/ipv4/conf/default/send_redirects) -eq 1 ];then
	echo "#Added for IPSec dual nic support" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
	sysctl -e -p >/dev/null
fi

if [ $(cat /proc/sys/net/ipv4/conf/default/accept_redirects) -eq 1 ];then
	echo "#Added for IPSec dual nic support" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	sysctl -e -p >/dev/null
fi

if [ $(cat /proc/sys/net/ipv4/ip_forward) -eq 0 ];then
	echo "#Added for IPSec support" >> /etc/sysctl.conf
	echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
	sysctl -e -p >/dev/null
fi
}

################################################################################################
#
#
function installIPSecServer() {

echo
echo "Setting this server as an IPSec host to be connected to."
echo

read -e -p "Server Public Interface: " -i $DEFAULT_PUBLICINTERFACE PUBLICINTERFACE
if [ ! -d /proc/sys/net/ipv4/conf/$PUBLICINTERFACE ];then echo "ERROR: device $PUBLICINTERFACE not found"; exit 1; fi

read -e -p "Server Private Interface: " -i $DEFAULT_PRIVATEINTERFACE PRIVATEINTERFACE
if [ ! -d /proc/sys/net/ipv4/conf/$PRIVATEINTERFACE ];then echo "ERROR: device $PRIVATEINTERFACE not found"; exit 1; fi

GUESS_PUBLICIP=$(ifconfig $PUBLICINTERFACE| grep inet | head -n1 | awk '{print $2;}' | cut -d":" -f2)
read -e -p "Server Public IP: " -i $GUESS_PUBLICIP ME
ping -c 1 $ME > /dev/null
if [ $? -ne 0 ];then echo "ERROR: IP $ME not pingable"; exit 1; fi

GUESS_PRIVATEIP=$(ifconfig $PRIVATEINTERFACE| grep inet | head -n1 | awk '{print $2;}' | cut -d":" -f2)
read -e -p "Server Private IP: " -i $GUESS_PRIVATEIP LOCALIP
ping -c 1 $LOCALIP > /dev/null
if [ $? -ne 0 ];then echo "ERROR: IP $ME not pingable"; exit 1; fi

read -e -p "IP Range IPSec server gives to dynamic clients: " -i "$DEFAULT_CLIENTRANGE" CLIENTRANGE

read -e -p "Pre Shared Key (PSK): " -i $DEFAULT_PSK IKEPSK
if [ -z $IKEPSK ];then echo "ERROR: PSK shouldn't be null. That's stupid."; exit 1; fi

read -e -p "IPSec Client Login: " -i $DEFAULT_LOGIN LOGIN
if [ -z $LOGIN ];then echo "ERROR: Login shouldn't be null."; exit 1; fi

read -e -p "IPSec Client Password: " -i $DEFAULT_PASS PASS
if [ -z $PASS ];then echo "ERROR: Login password shouldn't be null."; exit 1; fi

read -e -p "IPSec Client IP (* for dynamic): " -i $DEFAULT_IP IP
if [ "${IP}x" == "x" ];then echo "ERROR: Login IP shouldn't be null."; exit 1; fi

read -e -p "Private Network masks behind the IPSec VPN: " -i $DEFAULT_PRIVATE_NETWORKS PRIVATE_NETWORKS
if [ -z $PRIVATE_NETWORKS ];then echo "ERROR: Private Networks list shouldn't be null."; exit 1; fi

read -e -p "IPSec/VPN Profile Name (No spaces): " -i $DEFAULT_IPSECNAME IPSECNAME
if [ -z $IPSECNAME ];then echo "ERROR: IPSec profile name shouldn't be null."; exit 1; fi
VPNTUNNELNAME=$IPSECNAME
if [[ $IPSECNAME = *[[:space:]]* ]];then
echo "ERROR: Profile name can not have spaces."
exit 1;
fi


if [ -f /etc/init.d/ipsec ];then

	echo "Stopping exisitng ipsec and xl2tpd services..."
	/etc/init.d/ipsec stop
	/etc/init.d/xl2tpd stop

else

	if [ ! -f /etc/yum.repos.d/epel.repo ]; then
		echo "Installing EPEL repo..."
		yum -y install http://vesta.informatik.rwth-aachen.de/ftp/pub/Linux/fedora-epel/6/i386/epel-release-6-8.noarch.rpm > /dev/null
		if [ $? -ne 0 ];then echo "ERROR: EPEL repo install failed and this is required. Existing." exit 1; fi
	fi

	yum -y install xl2tpd openswan ppp lsof >/dev/null
	if [ $? -ne 0 ];then echo "ERROR: installing required packages."; exit 1; fi
	mv /etc/ipsec.conf /etc/ipsec.conf-DISTRO
	mv /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf-DISTRO

fi

setSysCTL

if [ ! -f /etc/ipsec.conf ];then
# this file really needs the tabs or it will not work
cat > "/etc/ipsec.conf" <<EOF
config setup
	nat_traversal=yes
	virtual_private=$PRIVATE_NETWORKS
	#if you turn this on you might have connection problems
	oe=off
	protostack=netkey
	plutoopts="--interface=$PUBLICINTERFACE"
conn $IPSECNAME
	authby=secret
	pfs=no
	auto=start
	keyingtries=3
	rekey=yes
	ikelifetime=8h
	keylife=1h
	type=tunnel
	left=$ME
	leftnexthop=%defaultroute
	leftprotoport=17/1701
	right=%any
	rightprotoport=17/%any
EOF
else
	echo
	echo "WARNING: the /etc/ipsec.conf file already exists and we don't want to overwrite it. Moving on with what exists."
fi

grep "$IKEPSK" /etc/ipsec.secrets >/dev/null
if [ $? -eq 0 ];then
	echo
	echo "The PSK key \"$IKEPSK\" was already found in /etc/ipsec.secrets, please make sure it is correct."
	echo
else
	echo "Creating /etc/ipsec.secrets with your key $ISKPSK for all connections..."
	echo "%any : PSK \"$IKEPSK\"" >> /etc/ipsec.secrets
fi



grep "global" /etc/xl2tpd/xl2tpd.conf 2>&1 >/dev/null
if [ $? -eq 0 ];then
        #already exists
        echo "/etc/xl2tpd/xl2tpd.conf [global] already exists already."
else
echo "
[global]
ipsec saref = yes
listen-addr = $ME
" >> /etc/xl2tpd/xl2tpd.conf
echo "/etc/xl2tpd/xl2tpd.conf [global] Setup."
fi

grep "lns default" /etc/xl2tpd/xl2tpd.conf 2>&1 >/dev/null
if [ $? -eq 0 ];then
        #already exists
        echo "/etc/xl2tpd/xl2tpd.conf [lns default] already exists already."
else
echo "
[lns default]
ip range = $CLIENTRANGE
local ip = $LOCALIP
refuse chap = yes
refuse pap = yes
require authentication = yes
name=vpn-server
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes

" >> /etc/xl2tpd/xl2tpd.conf
echo "/etc/xl2tpd/xl2tpd.conf [lns default] Setup."
fi


grep "lns default" /etc/xl2tpd/xl2tpd.conf 2>&1 >/dev/null
if [ $? -ne 0 ];then
	echo "ERROR: Failed to detect [lns default] section in /etc/xl2tpd/xl2tpd.conf."
	echo "* HINT: try to run this again with a blank /etc/xl2tpd/xl2tpd.conf file."
	exit
fi


grep "bryanandrewsorg_ipsec_setup" /etc/ppp/options.xl2tpd 2>&1 >/dev/null
if [ $? -eq 0 ];then
        #already exists
	echo "/etc/ppp/options.xl2tpd already exists and was created by this script. Skipping setup..."
else
cat > "/etc/ppp/options.xl2tpd" <<EOF
#created by bryanandrewsorg_ipsec_setup.sh
require-mschap-v2
#we can force the client to use these DNS servers if we want to
#ms-dns 8.8.8.8
#ms-dns 4.2.2.1
proxyarp
asyncmap 0
auth
crtscts
lock
mtu 1410
mru 1410
# this is to quickly detect a failed tunnel and close it
lcp-echo-failure 10
lcp-echo-interval 2
hide-password
modem
#debug
defaultroute
EOF
fi

grep "$LOGIN" /etc/ppp/chap-secrets 2>&1 >/dev/null
if [ $? -eq 0 ];then
	#already exists
	echo "A login for $LOGIN already exists in /etc/ppp/chap-secrets, please verify this is correct."
else
	echo "Adding IPSec client login $LOGIN, pass $PASS, IP $IP to /etc/ppp/chap-secrets..."
	echo "$LOGIN * $PASS $IP" >> /etc/ppp/chap-secrets
fi

echo "Making sure ipsec and xl2tpd are in rc3.d"
chkconfig ipsec on
chkconfig xl2tpd on

echo "Starting ipsec and xl2tpd now..."
/etc/init.d/ipsec start
/etc/init.d/xl2tpd start
# it takes a second or two
sleep 3s
echo "Verifying ipsec service status..."
ipsec verify
if [ $? -eq 0 ];then
	echo "IPSec is setup"
else
	echo
	echo "Please address the issues detected by \"ipsec verify\" if need be."
fi
}


################################################################################################
#
#
function install_OSPFd() {

#
# Start the ospfd setup for routing
#

read -e -p "Server Public Interface: " -i $DEFAULT_PUBLICINTERFACE PUBLICINTERFACE
if [ ! -d /proc/sys/net/ipv4/conf/$PUBLICINTERFACE ];then echo "ERROR: device $PUBLICINTERFACE not found"; exit 1; fi

read -e -p "Server Private Interface: " -i $DEFAULT_PRIVATEINTERFACE PRIVATEINTERFACE
if [ ! -d /proc/sys/net/ipv4/conf/$PRIVATEINTERFACE ];then echo "ERROR: device $PRIVATEINTERFACE not found"; exit 1; fi

if [ ! -d /etc/quagga ];then
	echo "Installing zebra and ospfd services..."
	yum -y install quagga >/dev/null
fi

echo "Verifying zebra and ospfd are in rc3.d"
chkconfig zebra on; chkconfig ospfd on

#
# do not broadcast a route to our public interface on the ospf VPN
#
export ETH0`ipcalc -p $(ip addr show dev $PUBLICINTERFACE | grep "inet " | cut -d" " -f6)`
# created $ETH0PREFIX=24
export ETH0`ipcalc -n $(ip addr show dev $PUBLICINTERFACE | grep "inet " | cut -d" " -f6)`
# created $ETH0NETWORK=1.2.3.0

# lets name the router the IP of our private interface
ROUTERID=$(ip addr show dev $PRIVATEINTERFACE | grep "inet " | cut -d" " -f6 | cut -f1 -d"/")

#
# setup ospfd.conf
#
grep "$HOSTNAME" /etc/quagga/ospfd.conf >/dev/null
if [ $? -eq 0 ];then
	echo "WARNING: /etc/quagga/ospfd.conf already setup with this host as hostname, skipping."
	echo "* Look at the setup script source code for examples of this file setup correctly."
	echo "* You probably want to add these settings:"
	echo
	echo "router ospf"
	echo " no network ${ETH0NETWORK}/${ETH0PREFIX} area 0"
	echo " network $ROUTEFOR area 0"
else
# almost all default, default password since the managment port is only bound to 127.0.0.1 anyway
cat > "/etc/quagga/ospfd.conf" <<EOF
hostname $HOSTNAME
password zebra
!
!debug ospf event
!debug ospf packet all
!
router ospf
 ospf router-id $ROUTERID
 redistribute connected
 ! ignore these devices
 passive-interface lo0
 passive-interface eth0
 passive-interface eth1
 ! route for all other connected networks
 network 0.0.0.0/0 area 0.0.0.0
 ! fail safe no to advertise routes to the nodes public interface
 no network ${ETH0NETWORK}/${ETH0PREFIX} area 0
!
log file /var/log/quagga/ospfd.log
EOF

# log file is rotated by default in centos6
echo "ospfd.conf setup"
fi

grep "ip forwarding" /etc/quagga/zebra.conf >/dev/null
if [ $? -eq 0 ];then
	echo "WARNING: /etc/quagga/zebra.conf already setup it seems, skipping."
else
cat > "/etc/quagga/zebra.conf" <<EOF
hostname $HOSTNAME
password zebra
interface eth0
ipv6 nd suppress-ra
interface eth1
ipv6 nd suppress-ra
ip forwarding
EOF

# assumed defaults worked in the lab
echo "zebra.conf setup"
fi

echo "Verifying config file ownership..."
chown quagga:quaggavt /etc/quagga/ospfd.conf
chown quagga:quaggavt /etc/quagga/zebra.conf

echo "Starting zebra and ospfd now..."
/etc/init.d/zebra start
if [ $? -ne 0 ];then echo "ERROR: zebra service problem"; exit 1; fi
/etc/init.d/ospfd start
if [ $? -ne 0 ];then echo "ERROR: ospfd service problem"; exit 1; fi

}

echo
show_menu
while [ opt != '' ]
    do
    if [[ $opt = "" ]]; then
            exit;
    else
        case $opt in
        1) installIPSecServer
	exit
        ;;

        2) installIPSecClient
	exit
        ;;

        3) install_OSPFd
	exit
        ;;

        4)exit;
        ;;

        x)exit;
        ;;

        \n)exit;
        ;;

        *)clear;
        echo "Pick an option from the menu";
        show_menu;
        ;;
    esac
fi
done

