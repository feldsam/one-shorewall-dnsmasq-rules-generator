# Opennebula shorewall/dnsmasq rules generator (one-shorewall-dnsmasq-rules-generator)

## This nodejs script generates

 - shorewall DNAT (forward) rules based on configuration in VM USER_TEMPLATE
 - dnsmasq config ip ranges and hosts based on mac addresses

## How to define port forward rules in Opennebula VM.USER_TEMPLATE

	port/protocol						ex. 80/tcp
											forwards tcp port 80 and default wan ip on gateway to port 80 on vm
										ex. 53/udp
											forwards udp port 53 and default wan ip on gateway to port 53 on vm
	
	port,port,port/protocol				ex. 25,80,110/tcp
											forwards tcp ports 25,80,110 and default wan ip on gateway to ports 25,80,110 on vm
	
	port:wan_ip/protocol				ex. 80:89.187.133.160/tcp
											forwards tcp port 80 and wan ip address 89.187.133.160 on gateway to port 80 on vm
	
	port,port:wan_ip/protocol			ex. 80,443:89.187.133.160/tcp
											forwards tcp ports 80,443 and wan ip address 89.187.133.160 on gateway to ports 80,443 on vm
	
	src_port:dest_port/protocol			ex. 1122:22/tcp
											forwards tcp port 1122 and default wan ip on gateway to port 22 on vm
	
	src_port:wan_ip:dest_port/protocol	ex. 1122:89.187.133.160:22/tcp
	
											forwards tcp port 1122 and wan ip address 89.187.133.160 on gateway to port 22 on vm
	
	More rules can be separated by pipe	ex. 1122:22/tcp|80/tcp|53/udp
