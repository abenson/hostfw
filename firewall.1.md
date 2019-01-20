% FIREWALL(1) iptables configuration generator | hostfw 0.6.4
%
% January 2019


# NAME

firewall - an easy to use front-end to iptables

# SYNOPSIS

firewall \[OPTIONS\]

# DESCRIPTION

This utility is designed to generate iptables-based rulesets quickly and easily.

The default is to allow any outbound traffic and drop any unsolicited inbound traffic. DHCP and some ICMP types are also allowed. All other traffic will be dropped.

# OPTIONS

## Script behavior.

-q
  ~ Makes changes without displaying status messages.

-s
  ~ Simulates actions, showing commands that'd be run. Combine with -q to generate an iptables script.

-S
  ~ Show rules after configuration.

## Absolutes.

-A
  ~ Allows everything. All other options are ignored.

-D
  ~ Denies everything. All other options are ignored.

## Ports

-ot \<...\>
  ~ Only allow the specified TCP ports outbound. Ports should be comma separated. Example: 80,443

-it \<...\>
  ~ Only allow the specified TCP ports inbound.

-ou \<...\>
  ~ Only allow the specified UDP ports outbound.

-iu \<...\>
  ~ Only allow the specified UDP ports inbound.

## Hosts

-ih \<file\>
  ~ Limit inbound traffic to only the hosts specified in the file. This affects all traffic except DHCP. The file should consist of one IP or CIDR range per line.

-oh \<file\>
  ~ Limit outbound traffic to only the hosts specified in the file.

-tt
  ~ Automatically set rules based on trusts.

Equivalent to: -ih /etc/trusted.hosts -oh $(cat /etc/trusted.hosts /etc/target.hosts)

-eh \<file\>
  ~ Excludes the target regardless of they're specified in either target or trusted files.

## Other

-r
  ~ Change the default action from DROP to REJECT, kindly sending the connecting host a TCP "reset" if they do not connect to an allowed port.

-p
  ~ Disable inbound ICMP Echo Request. Note: This does not disable the host's ability to respond, so trusted hosts will still receive a response.

-i
  ~ Enable responses for all types of ICMP.

-d
  ~ Disable DHCP. If the host is configured to use a static IP, then there is no need to have those ports open. Note: This will disable a servers ability to offer DHCP as well.

-l
  ~ Log all exceptions.

# EXAMPLE

Only allow tcp/22 inbound (like to allow remote management of a system).

    # firewall -it 22

Only allow a host to connect to a proxy (tcp/8888) on a specific host (192.168.0.3).

    # firewall -oh <(echo 192.168.0.3) -ot 8888

# AUTHORS

- Andrew Benson.
- Contributions from Austin Taylor, et al.

# COPYRIGHT

Copyright © 2016 Andrew Benson. License: MIT

