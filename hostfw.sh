#!/bin/sh

# Copyright (c) 2015, Andrew C. Benson
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.

#     * Neither the name of `hostfw` nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL ANDREW BENSON BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

VERSION="0.4.2"

# Simple host-based permit-by-exception iptables generation script.

# Global variables.
LOGEXCEPT="0"
RESETCONN="0"
ALLOWPING="1"
ALLOWDHCP="1"
ALLICMP="0"
OB_TCP=""
OB_UDP=""
IB_TCP=""
IB_UDP=""
OB_TARGS=""
IB_TARGS=""
EX_TARGS=""
AUTOTRUST="0"
ALLOWALL="0"
DENYALL="0"
SHOWRULES="0"
PRINTSTATUS="1"
DEFTRUST="/etc/trusted.hosts"
DEFTARGS="/etc/target.hosts"
DEFEXCLD="/etc/exclude.hosts"

# You must be root (uid=0) to set iptables rules.
if [ `id -u` != "0" ]; then
	echo "You must be root to run this command."
	exit
fi

IPTABLES=`which iptables 2>/dev/null`

# We want to make sure iptables is available before we attempt to create
# the rules.

if [ -z $IPTABLES ]; then
	echo "Unable to find \`iptables\` in path."
	exit
fi

version_and_quit()
{
	echo "`basename $0` v$VERSION; Copyright (c) 2015, Andrew C. Benson"
	echo
	echo You can find more information, leave feedback and feature requests, and
	echo find the latest version at the project page: http://github.com/abenson/hostfw
	exit
}

help_and_quit()
{
	echo "usage: `basename $0` <options>"
	cat <<-HELPMSG
	    -h                 This message.

	    -v                 Display version.

	    -r                 Send TCP RST instead of dropping packet.

	    -p                 Disallow incoming PING
	    -i                 Don't restrict ICMP types.
	    -d                 Disallow DHCP.

	    -tt                Automatically set rules based on /etc/trusted.hosts
                           and /etc/target.hosts

	    -ot <...>          Comma separated list of allowed TCP ports outbound.
	    -ou <...>          Comma separated list of allowed UDP ports outbound.

	    -it <...>          Comma separated list of allowed TCP ports inbound.
	    -iu <...>          Comma separated list of allowed UDP ports inbound.

	    -oh <targs.lst>    Restrict outbound to specified hosts.
	    -ih <trust.lst>    Restrict inbound to specified hosts.

	    -eh <excld.lst>    Exclude hosts, even if they are in targets/trusted.

	    -l                 Log exceptions.

	    -s                 Simulate only.
	    -q                 Quiet (don't display status messages)

	    -D                 Absolute deny all.
	    -A                 Absolute allow all.

	    -S                 Show rules after setting.

	Defaults:
	    Outbound connections will be allowed on all ports to all hosts.
	    Inbound connections will be limited to related outbound traffic.
	    DHCP will be enabled.
	    Ping responses will be enabled.
	    Unsolicited inbound connections will be dropped.

	Notes:

	    Combine -q and -s to generate a script.

	You can find more information, leave feedback and feature requests, and
	find the latest version at the project page: http://github.com/abenson/hostfw

	HELPMSG
	exit
}

while [ ! -z "$1" ]; do
	case "$1" in
		"-h" )
			help_and_quit ;;
		"-v" )
			version_and_quit ;;
		"-S" )
			SHOWRULES="1" ;;
		"-l" )
			LOGEXCEPT="1" ;;
		"-r" )
			RESETCONN="1";;
		"-p" )
			ALLOWPING="0" ;;
		"-i" )
			ALLICMP="1" ;;
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
		"-eh" )
			EX_TARGS="$2"
			shift ;;
		"-D" )
			DENYALL="1" ;;
		"-A" )
			ALLOWALL="1" ;;
		"-tt")
			AUTOTRUST="1" ;;
		"-s" )
			IPTABLES="echo $IPTABLES" ;;
		"-q" )
			PRINTSTATUS="0" ;;
		* )
			echo "Unknown option: $1"
			help_and_quit ;;
	esac
	shift
done

# Handy wrapper to clear the rules.
flush_rules()
{
	$IPTABLES -F INPUT
	$IPTABLES -F OUTPUT
	$IPTABLES -F FORWARD
}

# Handy wrapper to set the policy of each chain.
set_policy()
{
	$IPTABLES -P INPUT $1
	$IPTABLES -P OUTPUT $1
	$IPTABLES -P FORWARD $1
}

log_exceptions()
{
	$IPTABLES -A INPUT -m limit --limit 5/min -j LOG
	$IPTABLES -A OUTPUT -m limit --limit 5/min -j LOG
	$IPTABLES -A FORWARD -m limit --limit 5/min -j LOG
}

allow_localhost()
{
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Allowing traffic for localhost."
	fi
	$IPTABLES -I INPUT 1 -s 127.0.0.1/8 -d 127.0.0.1/8 -j ACCEPT
	$IPTABLES -I OUTPUT 1 -s 127.0.0.1/8 -d 127.0.0.1/8 -j ACCEPT
}

# Setup for autotrust.

if [ $AUTOTRUST -eq 1 ]; then
	if [ -f $DEFTRUST ] && [ -f $DEFTARGS ]; then
		OB_TARGS=$DEFTARGS
		IB_TARGS=$DEFTRUST
		if [ -f $DEFEXCLD ]; then
			EX_TARGS=$DEFEXCLD
		fi
	else
		echo "Make sure $DEFTRUST and $DEFTARGS exist."
	fi
fi

# While these are technically incompatible with any other options,
# we only care if they are issued with each other. We'll ignore
# the other options, but we won't know what to do with both of these.

if [ $ALLOWALL -eq 1 ] && [ $DENYALL -eq 1 ]; then
	echo "-A and -D are incompatible."
	echo
	help_and_quit
fi

# Formula is the same for each of these.
# 1. Clear all rules.
# 2. Set default policy.
# 3. Don't do anything else.

if [ $ALLOWALL -eq 1 ]; then
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Flushing rules..."
	fi
	flush_rules
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Allowing all..."
	fi
	set_policy 'ACCEPT'
	exit
fi

if [ $DENYALL -eq 1 ]; then
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Flushing rules..."
	fi
	flush_rules
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Disallowing all..."
	fi
	set_policy 'DROP'
	allow_localhost
	if [ $LOGEXCEPT -eq 1 ]; then
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Logging exceptions..."
		fi
		log_exceptions
	fi
	exit
fi

# Setting defaults. STIGs say DROP by default.
flush_rules
set_policy 'DROP'

if [ $LOGEXCEPT -eq 1 ]; then
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Logging exceptions..."
	fi
	log_exceptions
fi

if [ $RESETCONN -eq 1 ]; then
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Send tcp-reset for unwanted connections..."
	fi
	$IPTABLES -A INPUT -j REJECT
	$IPTABLES -A OUTPUT -j REJECT
	$IPTABLES -A FORWARD -j REJECT
fi

if [ -n "$EX_TARGS" ]; then
	cat $EX_TARGS | sed 's/#.*//' | egrep -o "(^|[^0-9.])((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(/[0-9][0-9]?)?($|[^0-9.])" | while read net; do
		$IPTABLES -I INPUT 1 -s $net -j DROP
		$IPTABLES -I OUTPUT 1 -d $net -j DROP
	done
fi

if [ $ALLOWDHCP -eq 1 ]; then
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Allowing DHCP..."
	fi
	$IPTABLES -I INPUT 1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT
	$IPTABLES -I OUTPUT 1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT
fi

# Allow related connections.
if [ $PRINTSTATUS -eq 1 ]; then
	echo "Allowing related connections..."
fi
$IPTABLES -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

if [ -z $OB_TARGS ]; then
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Allowing outbound ICMP..."
	fi
	if [ $ALLICMP -eq 0 ]; then
		$IPTABLES -I OUTPUT 1 -p icmp --icmp-type 8 -j ACCEPT
		$IPTABLES -I OUTPUT 1 -p icmp --icmp-type 0 -j ACCEPT
	else
		$IPTABLES -I OUTPUT 1 -p icmp -j ACCEPT
	fi
	if [ -z $OB_TCP ]; then
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Not limiting outbound TCP connections."
		fi
		$IPTABLES -I OUTPUT 1 -p tcp -j ACCEPT
	else
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Limiting outbound connections to TCP ports $OB_TCP."
		fi
		$IPTABLES -I OUTPUT 1 -p tcp -m multiport --dports $OB_TCP -j ACCEPT
	fi
	if [ -z $OB_UDP ]; then
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Not limiting outbound UDP connections."
		fi
		$IPTABLES -I OUTPUT 1 -p udp -j ACCEPT
	else
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Limiting outbound connections to UDP ports $OB_UDP."
		fi
		$IPTABLES -I OUTPUT 1 -p udp -m multiport --dports $OB_UDP -j ACCEPT
	fi
else
	if [ $AUTOTRUST -eq 1 ]; then
		cat $OB_TARGS $IB_TARGS
	else
		cat $OB_TARGS
	fi | sed 's/#.*//' | egrep -o "(^|[^0-9.])((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(/[0-9][0-9]?)?($|[^0-9.])" | while read net; do
		if [ $ALLOWPING -eq 1 ]; then
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Allow ping/traceroute to $net..."
			fi
			if [ $ALLICMP -eq 0 ]; then
				$IPTABLES -I OUTPUT 1 -d $net -p icmp --icmp-type 8 -j ACCEPT
				$IPTABLES -I OUTPUT 1 -d $net -p icmp --icmp-type 0 -j ACCEPT
			else
				$IPTABLES -I OUTPUT 1 -d $net -p icmp -j ACCEPT
			fi
		fi

		if [ -z $OB_TCP ]; then
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Limiting outbound TCP connections to $net."
			fi
			$IPTABLES -I OUTPUT 1 -d $net -p tcp -j ACCEPT
		else
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Limiting outbound TCP connections to $net on ports $OB_TCP."
			fi
			$IPTABLES -I OUTPUT 1 -d $net -p tcp -m multiport --dports $OB_TCP -j ACCEPT
		fi
		if [ -z $OB_UDP ]; then
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Limiting outbound UDP connections to $net."
			fi
			$IPTABLES -I OUTPUT 1 -d $net -p udp -j ACCEPT
		else
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Limiting outbound UDP connections to $net on ports $OB_UDP."
			fi
			$IPTABLES -I OUTPUT 1 -d $net -p udp -m multiport --dports $OB_UDP -j ACCEPT
		fi
	done
fi

if [ -z $IB_TARGS ]; then
	if [ $ALLOWPING -eq 1 ]; then
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Respond to pings..."
		fi
		if [ $ALLICMP -eq 0 ]; then
			$IPTABLES -I INPUT 1 -p icmp --icmp-type 8 -j ACCEPT
		else
			$IPTABLES -I INPUT 1 -p icmp -j ACCEPT
		fi
	fi

	if [ -z $IB_TCP ]; then
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Not allowing inbound TCP connections."
		fi
	else
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Allowing inbound TCP connections to ports $IB_TCP."
		fi
		$IPTABLES -I INPUT 1 -p tcp -m multiport --dports $IB_TCP -j ACCEPT
	fi
	if [ -z $IB_UDP ]; then
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Not allowing inbound UDP connections."
		fi
	else
		if [ $PRINTSTATUS -eq 1 ]; then
			echo "Allowing inbound UDP connections to ports $IB_UDP."
		fi
		$IPTABLES -I INPUT 1  -p udp -m multiport --dports $IB_UDP -j ACCEPT
	fi
else
	cat $IB_TARGS | sed 's/#.*//' | egrep -o "(^|[^0-9.])((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(/[0-9][0-9]?)?($|[^0-9.])" | while read net; do
		if [ $ALLOWPING -eq 1 ]; then
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Respond to pings from $net..."
			fi
			if [ $ALLICMP -eq 0 ]; then
				$IPTABLES -I INPUT 1 -s $net -p icmp --icmp-type 8 -j ACCEPT
			else
				$IPTABLES -I INTUT 1 -s $net -p icmp -j ACCEPT
			fi
		fi

		if [ -z $IB_TCP ]; then
			if [ $PRINTSTATUS -eq 1 ]; then
				#echo "Not allowing inbound TCP connections."
				echo "Allowing inbound TCP connections from $net..."
			fi
			$IPTABLES -I INPUT 1 -s $net -p tcp -j ACCEPT
		else
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Allowing inbound TCP connections from $net on ports $IB_TCP."
			fi
			$IPTABLES -I INPUT 1 -s $net -p tcp -m multiport --dports $IB_TCP -j ACCEPT
		fi

		if [ -z $IB_UDP ]; then
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Not allowing inbound UDP connections."
			fi
		else
			if [ $PRINTSTATUS -eq 1 ]; then
				echo "Allowing inbound UDP connections from $net on ports $IB_UDP."
			fi
			$IPTABLES -I INPUT 1 -s $net -p udp -m multiport --dports $IB_UDP -j ACCEPT
		fi
	done
fi

allow_localhost

# If requested so the rules just created.
if [ $SHOWRULES -eq 1 ]; then
	echo ""
	if [ $PRINTSTATUS -eq 1 ]; then
		echo "Applied rules:"
	fi
	$IPTABLES -S
fi
