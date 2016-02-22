#!/usr/local/bin/node

var fs = require("fs");
var crypto = require("crypto");
var ip = require("ip");
var sprintf = require("sprintf-js").sprintf;
var OpenNebula = require("OpenNebula");
var one = new OpenNebula("oneadmin:somepass", "http://oneHost:2633/RPC2");

var dnsmasqFile = "./dhcpConf";
var vnetId = 2;
var selfIp = "10.254.254.254";
var macPrefix = "02:00";
var shorewallRulesFile = "./shorewallRules";
var defaultWanIp = "89.187.133.166";
var defaultWanIpReservedPortsTcp = ["22", "80", "443", "2633", "29876", "5030"];
var defaultWanIpReservedPortsUdp = ["1194"];

generateDhcpConf(function(err, updated){
	if(err){
		console.log(err);
		process.exit(1);
	}
	
	console.log("DHCP Config: " + (updated ? "Updated" : "Nothing changed"));
});

generateShorewallRules(function(err, updated){
	if(err){
		console.log(err);
		process.exit(1);
	}
	
	console.log("Shorewall Rules: " + (updated ? "Updated" : "Nothing changed"));
});

/**
 * Reads vm.USER_TEMPLATE.PORTFORWARD
 * Valid formats are:
 *		port/protocol						ex. 80/tcp
 *												forwards tcp port 80 and default wan ip on gateway to port 80 on vm
 *											ex. 53/udp
 *												forwards udp port 53 and default wan ip on gateway to port 53 on vm
 *
 *		port,port,port/protocol				ex. 25,80,110/tcp
 *												forwards tcp ports 25,80,110 and default wan ip on gateway to ports 25,80,110 on vm
 *
 *		port:wan_ip/protocol				ex. 80:89.187.133.160/tcp
 *												forwards tcp port 80 and wan ip address 89.187.133.160 on gateway to port 80 on vm
 *
 *		port,port:wan_ip/protocol			ex. 80,443:89.187.133.160/tcp
 *												forwards tcp ports 80,443 and wan ip address 89.187.133.160 on gateway to ports 80,443 on vm
 *
 *		src_port:dest_port/protocol			ex. 1122:22/tcp
 *												forwards tcp port 1122 and default wan ip on gateway to port 22 on vm
 *
 *		src_port:wan_ip:dest_port/protocol	ex. 1122:89.187.133.160:22/tcp
 *
 * 												forwards tcp port 1122 and wan ip address 89.187.133.160 on gateway to port 22 on vm
 *
 * More rules can be separated by pipe		ex. 1122:22/tcp|80/tcp|53/udp
 */
function generateShorewallRules(callback){
	// holds DNAT rules
	var rules = [];
	// holds used ports by vms
	var usedPorts = {"tcp": {}, "udp": {}};
	// holds requested ports
	var requestedPorts = {"tcp": {}, "udp": {}};
	
	// load used ports
	loadUsedPortsFromFile(function(err, data){
		if(err) return callback(err);
		
		if(data) usedPorts = data;
	});
	
	one.getVMs(function(err, vms){
		if(err) return callback(err);
		
		for(k1 in vms){
			var vm = vms[k1];
			var ip = getVMIp(vm);

			// check for IP
			if(!ip) continue;

			// check for context
			if(vm.USER_TEMPLATE.PORTFORWARD == undefined) continue;
			
			// explode rules
			var portforwards = vm.USER_TEMPLATE.PORTFORWARD.split("|");

			for(k2 in portforwards){
				
				// match pattern
				var pattern = /^((?:[0-9]{1,5},?)+)\:?((?:[0-9]{1,3}\.){3}[0-9]{1,3})?\:?((?:[0-9]{1,5},?)*)\/(tcp|udp)/g;
				
				var m = pattern.exec(portforwards[k2]);

				// invalid value
				if(!m) continue;
				
				var wanIp = defaultWanIp;
				if(m[2] != undefined){
					wanIp = m[2];
				}
				
				// set wan Ip if not exists
				if(requestedPorts[m[4]][wanIp] == undefined){
					requestedPorts[m[4]][wanIp] = {};
				}
				
				// vm ID and
				if(requestedPorts[m[4]][wanIp][vm.ID] == undefined){
					requestedPorts[m[4]][wanIp][vm.ID] = {};
				}
				
				// set ports
				requestedPorts[m[4]][wanIp][vm.ID][k2] = { ip: ip, srcPorts: m[1].split(","), destPorts: m[3].split(","), rule: portforwards[k2]};
			}
		}
		
		// iterate over used ports and delete not existing one
		for(protocol in usedPorts){
			var wanIps = usedPorts[protocol];
			
			for(wanIp in wanIps){
				var ports = wanIps[wanIp];
				
				for(port in ports){
					var vmId = ports[port];

					// port forward was deleted
					if(requestedPorts[protocol][wanIp][vmId] == undefined){
						delete usedPorts[protocol][wanIp][port];
						continue;
					}
					
					// check for ports
					var rulePorts = [];
					for(ruleId in requestedPorts[protocol][wanIp][vmId]){
						rulePorts = rulePorts.concat(requestedPorts[protocol][wanIp][vmId][ruleId].srcPorts);
					}
						
					if(rulePorts.indexOf(port) > -1 && usedPorts[protocol][wanIp][port] != vmId){
						delete usedPorts[protocol][wanIp][port];
					}
					
					if(rulePorts.indexOf(port) == -1 && usedPorts[protocol][wanIp][port] == vmId){
						delete usedPorts[protocol][wanIp][port];
					}
					
				}
			}
		}
		
		// iterate over requested ports and create DNAT rules
		var errors = {};
		for(protocol in requestedPorts){
			var wanIps = requestedPorts[protocol];
			
			for(wanIp in wanIps){
				var vmIds = wanIps[wanIp];
				
				for(vmId in vmIds){
					var ruleIds = vmIds[vmId];
					
					if(errors[vmId] == undefined){
						errors[vmId] = [];	
					}
					
					for(ruleId in ruleIds){
						var srcPorts = ruleIds[ruleId].srcPorts;
						var destPorts = ruleIds[ruleId].destPorts;

						createDnatRules(protocol, ip, srcPorts, destPorts, wanIp, vmId, function(err){
							if(err) errors[vmId].push(err);
						});
					}
				}
			}
		}

		// check for errors
		for(vmId in errors){
			var vmErrors = errors[vmId];
			
			// no errors, so skip
			if(vmErrors.length == 0) continue;
			
			one.getVM(parseInt(vmId)).update('PORTFORWARD_ERROR="' + vmErrors.join("\n") + '"', 1, function(err){
				if(err) return callback(err);
			});
		}
		
		// save used ports
		saveUsedPortsToFile(function(err){
			if(err) return callback(err);
		});
		
		// save dnat shorewall rules
		var dnatRules = "";
		for(vmId in rules){
			var vmRules = rules[vmId];
			
			// add comment
			dnatRules += "# Forward rules for VM ID: " + vmId + "\n" + vmRules.join("\n") + "\n";
		}
		
		getChecksumOfFile(shorewallRulesFile, function(err, hash){
			if(err) return callback(err);
			
			// are there some changes?
			if(getChecksum(dnatRules) != hash){
				return fs.writeFile(shorewallRulesFile, dnatRules, function(err){
					if(err) return callback(err);
					callback(null, true);
				});
			}
			
			callback(null, false);
		});
	});
	
	function createDnatRules(protocol, ip, srcPorts, destPorts, wanIp, vmId, callback){
		for(k in srcPorts){
			var port = srcPorts[k];
			
			isPortAvailable(protocol, port, wanIp, vmId, function(err){
				if(err) return callback(err);
				
				// create vm in rules
				if(rules[vmId] == undefined){
					rules[vmId] = [];
				}

				if(destPorts.length == 1 && destPorts[0] == ""){
					return rules[vmId].push("DNAT		net		prv:" + ip + "	" + protocol + "	" + port + "	-		" + wanIp);
				}
				
				if(destPorts.length > 0 && destPorts[0] != ""){
					return rules[vmId].push("DNAT		net		prv:" + ip + ":" + destPorts[k] + "	" + protocol + "	" + port + "	-		" + wanIp);
				}
			});
		}
	}
	
	function isPortAvailable(protocol, port, wanIp, vmId, callback){
		// check for defalt wan IP reserved ports
		if(wanIp == defaultWanIp){
			if(protocol == "tcp" && defaultWanIpReservedPortsTcp.indexOf(port) > -1){
				return callback(port + "/tcp is reserved port!");
			}
			
			if(protocol == "udp" && defaultWanIpReservedPortsUdp.indexOf(port) > -1){
				return callback(port + "/udp is reserved port!");
			}
		}
	
		// create wanIp
		if(usedPorts[protocol][wanIp] == undefined){
			usedPorts[protocol][wanIp] = {};
		}
	
		// check for used ports
		if(usedPorts[protocol][wanIp][port] != undefined && usedPorts[protocol][wanIp][port] != vmId){
			return callback(port + "/" + protocol + " is used by VMID " + usedPorts[protocol][wanIp][port] + "!");
		}
		
		// port available, so save
		usedPorts[protocol][wanIp][port] = vmId;
		
		callback(null);
	}
	
	function saveUsedPortsToFile(callback){
		var json = JSON.stringify(usedPorts);
	
		fs.writeFile("./usedPorts.json", json, function(err){
			if(err) return callback(err);
			
			callback(null);
		});
	}
	
	function loadUsedPortsFromFile(callback){
		fs.readFile("./usedPorts.json", function(err, body){
			if(err){
				if(err.code !== 'ENOENT'){
					return callback(err);
				}
				
				return callback(null, null);
			}
			
			try{
				callback(null, JSON.parse(body));
			}
			catch(err){
				callback(err);
			}
		});
	}
}

function getVMIp(vm){
	var nic = vm.TEMPLATE.NIC;

	if(nic.NETWORK_ID != undefined){
		nic = Array(nic);
	}
	
	for(k in nic){
		var net = nic[k];
		
		// find desired network
		if(net.NETWORK_ID == vnetId){
			return net.IP;
		}
	}
	
	return false;
}

function generateDhcpConf(callback){
	var vnet = one.getVNet(vnetId);

	vnet.info(function(err, data){
		if(err) return callabck(err);
		
		var dhcpRange = [];
		var dhcpHost = [];
		
		for(k1 in data.VNET.AR_POOL.AR){
			var ar = data.VNET.AR_POOL.AR[k1];
			
			if(ar.IP != selfIp){
				dhcpRange.push("dhcp-range=" + ar.IP + "," + ar.IP_END + ",infinite");
				
				var startIpLong = ip.toLong(ar.IP);
				var size = parseInt(ar.SIZE);
				var endIpLong = startIpLong + size;
				
				for(x = startIpLong; x < endIpLong; x++){
					var hostIp = ip.fromLong(x);
					var hostMac = ip2mac(hostIp);
					dhcpHost.push("dhcp-host=" + hostMac + "," + hostIp);
				}
			}
		}
		
		var dhcpConf = dhcpRange.join("\n") + "\n" + dhcpHost.join("\n");
		
		getChecksumOfFile(dnsmasqFile, function(err, hash){
			if(err) return callback(err);
			
			// are there some changes?
			if(getChecksum(dhcpConf) != hash){
				return fs.writeFile(dnsmasqFile, dhcpConf, function(err){
					if(err) return callback(err);
					callback(null, true);
				});
			}
			
			callback(null, false);
		});
	});
}

function getChecksumOfFile(path, callback){
	var fd = fs.createReadStream(path);
	var hash = crypto.createHash("md5");
	hash.setEncoding("hex");
	
	fd.on("end", function(){
	    hash.end();
	    callback(null, hash.read());
	});
	
	fd.on("error", function(err){
		callback(err);
	});
	
	fd.pipe(hash);
}

function getChecksum(data){
	var hash = crypto.createHash("md5");
	hash.setEncoding('hex');
	hash.write(data);
	hash.end();
	return hash.read();
}

function ip2mac(ip){
	var mac = macPrefix;
	
	var parts = ip.split(".");
	
	for(k in parts){
		mac += ":" + sprintf("%02x", parseInt(parts[k]));
	}
	
	return mac;
}

function extend(target) {
    var sources = [].slice.call(arguments, 1);
    sources.forEach(function (source) {
        for (var prop in source) {
            target[prop] = source[prop];
        }
    });
    return target;
}