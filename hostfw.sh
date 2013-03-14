#!/bin/sh

# Simple host-based permit-by-exception iptables generation script.

# Global variables.
LOGEXCEPT="0"
RESETCONN="0"
ALLOWPING="1"
ALLOWDHCP="1"
OB_TCP=""
OB_UDP=""
IB_TCP=""
IB_UDP=""
OB_TARGS=""
IB_TARGS=""
ALLOWALL="0"
DENYALL="0"
SHOWRULES="0"

IPTABLES=`which iptables 2>/dev/null`

# We want to make sure iptables is available before we attempt to create 
# the rules.

if [ -z $IPTABLES ]; then
	echo Unable to find \`iptables\` in path.
	exit
fi

function help_and_quit
{
	echo "usage: $0 <options>"
cat <<HELPMSG
	-h                 This message.

	-r                 Send TCP RST instead of dropping packet.

	-p                 Disallow incoming PING

	-d                 Disallow DHCP.

	-ot <...>          Comma separated list of allowed TCP ports outbound.
	-ou <...>          Comma separated list of allowed UDP ports outbound.

	-it <...>          Comma separated list of allowed TCP ports inbound.
	-iu <...>          Comma separated list of allowed UDP ports inbound.

	-oh <targs.lst>    Restrict outbound to specified hosts.
	-ih <trust.lst>    Restrict inbound to specified hosts.

	-l                 Log exceptions.

	-D                 Absolute deny all.
	-A                 Absolute allow all.

	-S                 Show rules after setting.

Defaults:
	Outbound connections will be allowed on all ports to all hosts.
	Inbound connections will be limited to related outbound traffic.
	DHCP will be enabled.
	Ping responses will be enabled.
	Unsolicited inbound connections will be dropped.

HELPMSG
	exit
}

while [ ! -z "$1" ]; do 
	case "$1" in
		"-h" )
			help_and_quit ;;
		"-S" )
			SHOWRULES="1" ;;
		"-l" )
			LOGEXCEPT="1" ;;
		"-r" )
			RESETCONN="1";;
		"-p" )
			ALLOWPING="0" ;;
		"-d" )
			ALLOWDHCP="0" ;;
		"-ot" )
			OB_TCP="$2" 
			shift ;;
		"-ou" )
			OB_UDP="$2"
			shift ;;
		"-it" )
			IB_TCP="$2"
			shift ;;
		"-iu" )
			IB_UDP="$2"
			shift ;;
		"-oh" )
			OB_TARGS="$2"
			shift ;;
		"-ih" )
			IB_TARGS="$2"
			shift ;;
		"-D" )
			DENYALL="1" ;;
		"-A" )
			ALLOWALL="1" ;;
	esac
	shift
done

# Handy wrapper to clear the rules. 
function flush_rules
{
	$IPTABLES -F INPUT
	$IPTABLES -F OUTPUT
	$IPTABLES -F FORWARD
} 

# Handy wrapper to set the policy of each chain. 
function set_policy
{
	$IPTABLES -P INPUT $1
	$IPTABLES -P OUTPUT $1
	$IPTABLES -P FORWARD $1
}

# While these are technically incompatible with any other options,
# we only care if they are issued with each other. We'll ignore
# the other options, but we won't know what to do with both of these.

if [ $ALLOWALL -eq 1 ] && [ $DENYALL -eq 1 ]; then
	echo -A and -D are incompatible. 
	echo
	help_and_quit
fi

# Formula is the same for each of these. 
# 1. Clear all rules.
# 2. Set default policy.
# 3. Don't do anything else.

if [ $ALLOWALL -eq 1 ]; then
	echo "Flushing rules..."
	flush_rules
	echo "Allowing all..."
	set_policy 'ACCEPT'
	exit
fi

if [ $DENYALL -eq 1 ]; then
	echo "Flushing rules..."
	flush_rules
	echo "Allowing all..."
	set_policy 'DROP'
	exit
fi

# Setting defaults. STIGs say DROP by default.
flush_rules
set_policy 'DROP'

if [ $LOGEXCEPT -eq 1 ]; then
	echo Logging exceptions...
	logger=""
	lsmod | grep -q "ipt_LOG"
	if [ $? -eq 0 ]; then
		logger="LOG"
	fi
	lsmod | grep -q "ipt_ULOG"
	if [ $? -eq 0 ]; then
		logger="ULOG"
	fi
	if [ -z $logger ]; then
		echo "Please configure a valid logging method."
	fi
	$IPTABLES -A INPUT -j $logger
	$IPTABLES -A OUTPUT -j $logger
	$IPTABLES -A FORWARD -j $logger
fi

if [ $RESETCONN -eq 1 ]; then
	echo Send tcp-reset for unwanted connections...
	$IPTABLES -A INPUT -j REJECT
	$IPTABLES -A OUTPUT -j REJECT
	$IPTABLES -A FORWARD -j REJECT
fi

if [ $ALLOWDHCP -eq 1 ]; then
	echo Allowing DHCP...
	$IPTABLES -I INPUT 1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT
	$IPTABLES -I OUTPUT 1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT
fi

# Allow related connections.
$IPTABLES -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

if [ -z $OB_TARGS ]; then
	if [ -z $OB_TCP ]; then
		echo Not limiting outbound TCP connections.
		$IPTABLES -I OUTPUT 1 -p tcp -j ACCEPT
	else
		echo Limiting outbound connections to TCP ports $OB_TCP.
		$IPTABLES -I OUTPUT 1 -p tcp -m multiport --dports $OB_TCP -j ACCEPT
	fi
	if [ -z $OB_UDP ]; then
		echo Not limiting outbound UDP connections.
		$IPTABLES -I OUTPUT 1 -p udp -j ACCEPT
	else
		echo Limiting outbound connections to UDP ports $OB_UDP.
		$IPTABLES -I OUTPUT 1 -p udp -m multiport --dports $OB_UDP -j ACCEPT
	fi
else
	cat $OB_TARGS | sed 's/#.*//' | egrep -o "(^(?:(?:1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}(?:1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))(?:\/((?:[12]?[0-9])|(?:3[012])))?$" | while read net; do
		if [ -z $OB_TCP ]; then
			echo Limiting outbound TCP connections to $net.
			$IPTABLES -I OUTPUT 1 -d $net -p tcp -j ACCEPT
		else
			echo Limiting outbound TCP connections to $net on ports $OB_TCP.
			$IPTABLES -I OUTPUT 1 -d $net -p tcp -m multiport --dports $OB_TCP -j ACCEPT
		fi
		if [ -z $OB_UDP ]; then
			echo Limiting outbound UDP connections to $net.
			$IPTABLES -I OUTPUT 1 -d $net -p udp -j ACCEPT
		else
			echo Limiting outbound UDP connections to $net on ports $OB_UDP.
			$IPTABLES -I OUTPUT 1 -d $net -p udp -m multiport --dports $OB_UDP -j ACCEPT
		fi
	done
fi

if [ -z $IB_TARGS ]; then
	if [ $ALLOWPING -eq 1 ]; then
		echo Respond to pings...
		$IPTABLES -I INPUT 1 -p icmp --icmp-type 8 -j ACCEPT
	fi

	if [ -z $IB_TCP ]; then
		echo Not allowing inbound TCP connections.
	else
		echo Allowing inbound TCP connections to ports $IB_TCP.
		$IPTABLES -I INPUT 1 -p tcp -m multiport --dports $IB_TCP -j ACCEPT
	fi
	if [ -z $IB_UDP ]; then
		echo Not allowing inbound UDP connections.
	else
		echo Allowing inbound UDP connections to ports $IB_UDP.
		$IPTABLES -I INPUT 1  -p udp -m multiport --dports $IB_UDP -j ACCEPT
	fi
else
	cat $IB_TARGS | sed 's/#.*//' | egrep -o "(^(?:(?:1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}(?:1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))(?:\/((?:[12]?[0-9])|(?:3[012])))?$" | while read net; do
		if [ $ALLOWPING -eq 1 ]; then
			echo Respond to pings from $net...
			$IPTABLES -I INPUT 1 -s $net -p icmp --icmp-type 8 -j ACCEPT
		fi

		if [ -z $IB_TCP ]; then
			echo Not allowing inbound TCP connections.
		else
			echo Allowing inbound TCP connections from $net on ports $IB_TCP.
			$IPTABLES -I INPUT 1 -s $net -p tcp -m multiport --dports $IB_TCP -j ACCEPT
		fi
		
		if [ -z $IB_UDP ]; then
			echo Not allowing inbound UDP connections.
		else
			echo Allowing inbound UDP connections from $net on ports $IB_UDP.
			$IPTABLES -I INPUT 1 -s $net -p udp -m multiport --dports $IB_UDP -j ACCEPT
		fi
	done
fi

# Allow localhost traffic.
$IPTABLES -I INPUT 1 -s 127.0.0.1/8 -d 127.0.0.1 -j ACCEPT
$IPTABLES -I OUTPUT 1 -s 127.0.0.1/8 -d 127.0.0.1 -j ACCEPT

if [ $SHOWRULES -eq 1 ]; then
	$IPTABLES -S
fi
