from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoTimeoutException, AuthenticationException, SSHException
from getpass import getpass
import ipaddress, sys

def get_audit_targets():
    """Reads text file 'to_audit.txt' to get device and port."""
    audit_target = []

    with open('to_audit.txt', 'r', encoding='utf-8') as f:
        for line in f.readlines():
            audit_target.append(line.strip())
        
    if len(audit_target) < 2:
        raise ValueError('Input file must contain at least two non-empty lines: device and port.')
    
    device = audit_target[0]
    port = audit_target[1]
    
    valid_prefixes = ('ge', 'xe', 'et')
    
    # Valid Juniper customer port prefixes
    if not port.startswith(valid_prefixes):
        raise ValueError(f"{port} is invalid. Valid ports must start with 'ge', 'xe', or 'et'. ")
    
    return device, port

def get_device_creds(device):
    """Gather creds to use to SSH into device"""
    username = input('Enter username: ').strip()
    password = getpass('Enter password: ')
        
    creds = {
        "device_type": 'juniper',
        "host": device,
        "username": username,
        "password": password
                }
    
    return creds

def establish_session(creds):
    """SSH to device"""
    connection = ConnectHandler(**creds)
    print(f"Connected to {creds['host']}")
    
    return connection

def check_interface_exists(connection, port):
    """Validate the interface exists before running commands to scrape config"""
    
    # Error patterns when interface doesn't exist
    errors = ['error', 'not found', 'unknown interface', 'syntax error']
    
    print(f'Checking port {port} exists...')
    output = connection.send_command(f'show interfaces {port} terse')
    lowered_output = output.lower()
    
    for error in errors:
        # Interface does not exist
        if error in lowered_output:
            return False
        
    # If any line in output starts with port, port exists
    lines = output.splitlines()
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(port):
            return True
        
    # Fallback if not caught by above
    return False
   
def get_config(connection, port):
    """Run main commands to grab port config, static routes, and bgp peers"""
    
    device_config = {}
    
    # Send commands and store in dict
    try:
        print(f'Running command show interfaces {port} ...')
        device_config['show_interface'] = connection.send_command(f'show interfaces {port}')
    except Exception as exc:
        raise RuntimeError(f"Could not run command 'show interfaces {port}': {exc}")
  
    try:
        print(f'Running command show configuration interfaces {port} | display set ...')
        device_config['config_interface'] = connection.send_command(f'show configuration interfaces {port} | display set')
    except Exception as exc:
        raise RuntimeError(f"Could not run command 'show configuration interfaces {port} | display set': {exc}")
    
    try:
        print('Running command show configuration routing-options static | display set ...')
        device_config['config_static_routes'] = connection.send_command(f'show configuration routing-options static | display set')
    except Exception as exc:
        raise RuntimeError(f"Could not run command 'show configuration routing-options static | display set': {exc}")
    
    try:
        print('Running command show configuration protocols bgp group C-CUST | display set | match neighbor ...')
        device_config['config_bgp_neighbors'] = connection.send_command(f'show configuration protocols bgp group C-CUST | display set | match neighbor')
    except Exception as exc:
        raise RuntimeError(f"Could not run command 'show configuration protocols bgp group C-CUST | display set | match neighbor': {exc}")
  
    return device_config

def validate_required_outputs(device_config):
    """Validate presence of keys and values of command outputs before proceeding"""
    
    # Required keys to check
    required_keys = ['show_interface',
                     'config_interface',
                     'config_static_routes',
                     'config_bgp_neighbors']
    
    # Append if any problems found
    problems = []
    
    # Check required keys are present in dict
    for key in required_keys:
        if key not in device_config:
            problems.append(f'Missing key: {key}')
            # Skip value checks if key is not present
            continue
        
        value = device_config[key]
        
        # Value check: None
        if value == None:
            problems.append(f'Key present, but value None: {key}')
            continue
        
        # Value check: Type check
        if not isinstance(value, str):
            problems.append(f'Key is present, but is not a string: {key}')
            continue
        
        # Value check: Empty check
        if value == "":
            problems.append(f'Key is present, but is empty: {key}')
            continue
    
    # If any problems were found, return an error and exit the program
    if problems:
        message = f'Validation error found: {problems}'
        raise RuntimeError(message)
        
    # No issues found with command output, so go ahead and return device_config dict
    
def audit_interface(device_config, device):
    """Network audit for interface config"""
    
    # Initialise audit dict with defaults
    network_audit = {
        'device': device,
        'interface': 'Unknown',
        'interface_type': 'Unknown',
        'description': 'Unknown',
        'configuration': [],
        'ipv4_wan': set(),
        'ipv6_wan': set(),
        'static_route': set(),
        'peer_as': 'Unknown',
        'bgp_peer_v4': 'Unknown',
        'import_policy_v4': set(),
        'export_policy_v4': set(),
        'v4_bgp_prefixes': set(),
        'bgp_peer_v6': 'Unknown',
        'import_policy_v6': set(),
        'export_policy_v6': set(),
        'v6_bgp_prefixes': set(),
        }
    
    # Temp storage of interface config
    interface_info = {}
    interface_info['interface_type'] = 'Unknown'
    interface_info['interface'] = 'Unknown'
    interface_info['description'] = 'Unknown'
    interface_info['ipv4_wans'] = set()
    interface_info['ipv6_wans'] = set()
    
    # Extract port speed
    if device_config['show_interface']:
        lines = device_config['show_interface'].splitlines()
        
        for line in lines:
            if 'Speed:' in line:
                parts = line.split()
                type_index = parts.index('Speed:') + 1
                if parts[type_index].endswith(','):
                    interface_info['interface_type'] = parts[type_index].rstrip(',')
    
    # Extract interface config
    if device_config['config_interface']:
        lines = device_config['config_interface'].splitlines()
        
        for line in lines:
            parts = line.split()
            
            # Interface
            if 'interfaces' in parts:
                interface_index = parts.index('interfaces') + 1
                interface_info['interface'] = parts[interface_index]
                
            # Description
            if 'description' in parts:
                desc_index = parts.index('description') + 1
                interface_info['description'] = parts[desc_index]
                
            # IPv4 
            if 'inet' in parts and 'address' in parts:
                ipv4_wan_index = parts.index('address') + 1
                interface_info['ipv4_wans'].add(parts[ipv4_wan_index])
            
            # IPv6
            if 'inet6' in parts and 'address' in parts:
                ipv6_wan_index = parts.index('address') + 1
                interface_info['ipv6_wans'].add(parts[ipv6_wan_index])
                
    # Update network audit interface config from temp dict
    network_audit['interface'] = interface_info['interface']
    network_audit['interface_type'] = interface_info['interface_type']
    network_audit['description'] = interface_info['description']
    network_audit['ipv4_wan'] = interface_info['ipv4_wans']
    network_audit['ipv6_wan'] = interface_info['ipv6_wans']
    
    # Update service type
    if 'vrrp' in device_config['config_interface']:
        network_audit['configuration'].append('vrrp')
    
    return network_audit

# Extract static routes
def audit_static_routes(device_config, network_audit):
    """Check static routes for any matches against interface IP subnet"""
    
    if network_audit['ipv4_wan']:
        lines = device_config['config_static_routes'].splitlines()
    
        static_routes = []
        static_routes_non_ip_nh = []
        current_route = None
        current_next_hop = None

        for line in lines:
             if 'static' in line and 'next-hop' in line:
                
                parts = line.split()
                
                # Use index of route and nh
                route_index = parts.index('route') + 1
                next_hop_index = parts.index('next-hop') + 1
                
                current_route = parts[route_index]
                current_next_hop = parts[next_hop_index]
                
                # Make true only next-hop is not a valid IP address
                skip_flag = False
                
                try:
                    ipaddress.ip_address(current_next_hop)
                except ValueError:
                    skip_flag = True
                    # Static routes with non-ip next-hops
                    static_routes_non_ip_nh.append((current_route, current_next_hop))
                    
                # If next-hop is not a valid IP, skip this iteration in the loop
                if skip_flag:
                    continue
                    
                # Static routes with ip next-hops
                static_routes.append((current_route, current_next_hop))
            
        # Check if next-hop of static routes fall within allocated IP subnet
        ipv4_set = network_audit['ipv4_wan']
        
        # Temp storage for static routes
        static_route_set = set()

        for route in static_routes:
            # Make an ipv4 network and ipv4 address for each route and next-hop
            route_ipv4_net = ipaddress.ip_network(route[0])
            next_hop_ipv4 = ipaddress.ip_address(route[1])
            for ipv4 in ipv4_set:
                # Make an ipv4 address for interface IP address
                ipv4_net = ipaddress.ip_network(ipv4, strict=False)
                # Check if the next-hop is in the subnet for the ipv4 address
                if next_hop_ipv4 in ipv4_net:
                    static_route = str(route_ipv4_net)
                    static_route_set.add(static_route)
                    
                    network_audit['static_route'] = static_route_set
        
        # Update service type
        if network_audit['static_route']:
            network_audit['configuration'].append('static')
                    
    else:
        network_audit['static_route'] = 'Static routes unknown'
        
    return network_audit

# Extract BGP peers
def audit_bgp(device_config, network_audit):
    """Extract BGP peer info"""
    
    if network_audit['ipv4_wan']:
        # List for peer info
        bgp_peer_info = []
        # Temp storage dict of peer info
        peers = {}

        # Split config string into lines
        lines = device_config['config_bgp_neighbors'].splitlines()
        
        # Split config lines into parts
        for line in lines:
            parts = line.split()

            # Extract peer ip
            if 'neighbor' in parts:
                peer_index = parts.index('neighbor') + 1
                peer = parts[peer_index]
            
                # If peer isn't already in the dict, add dict entry
                if peer not in peers:
                    peers[peer] = {
                        'peer_as': None,
                        'import_policy': set(),
                        'export_policy': None
                        }
                
                # Extract peer-as and update dict
                if 'peer-as' in parts:
                    peer_index = parts.index('peer-as') + 1
                    peers[peer]['peer_as'] = parts[peer_index]
                
                # Extract import policy and update dict
                if 'import' in parts:
                    import_policy_index = parts.index('import') + 1
                    peers[peer]['import_policy'].add(parts[import_policy_index])
                
                # Extract export policy and update dict
                if 'export' in parts:
                    export_policy_index = parts.index('export') + 1
                    peers[peer]['export_policy'] = parts[export_policy_index]
        
        # Build list of tuples for checking against allocated IP
        for peer, peer_info in peers.items():
            current_peer = peer
            current_peer_as = peer_info['peer_as']
            current_import_policy = peer_info['import_policy']
            current_export_policy = peer_info['export_policy']
            
            bgp_peer_info.append((current_peer, current_peer_as, current_import_policy, current_export_policy))
        
        # Find matching peer based on allocated ip
        for bgp_peer in bgp_peer_info:
            peer_ipaddr = ipaddress.ip_address(bgp_peer[0])
            # Check and add IPv4 peer to audit
            if type(peer_ipaddr) == ipaddress.IPv4Address:
                for ipv4 in network_audit['ipv4_wan']:
                    ipv4_net = ipaddress.ip_network(ipv4, strict = False)
                    if peer_ipaddr in ipv4_net:
                        network_audit['bgp_peer_v4'] = bgp_peer[0]
                        network_audit['peer_as'] = bgp_peer[1]
                        network_audit['import_policy_v4'] = bgp_peer[2]
                        network_audit['export_policy_v4'] = bgp_peer[3]
                        
            # Check and add IPv6 peer to audit
            if type(peer_ipaddr) == ipaddress.IPv6Address:
                for ipv6 in network_audit['ipv6_wan']:
                    ipv6_net = ipaddress.ip_network(ipv6, strict = False)
                    if peer_ipaddr in ipv6_net:
                        network_audit['bgp_peer_v6'] = bgp_peer[0]
                        network_audit['peer_as'] = bgp_peer[1]
                        network_audit['import_policy_v6'] = bgp_peer[2]
                        network_audit['export_policy_v6'] = bgp_peer[3]
                        
    # Check peer-as is not Falsy before checking if it is a digit
    if network_audit['peer_as'] and str(network_audit['peer_as']).isdigit():
        # Update service type BGP
        network_audit['configuration'].append('bgp')
        
    # Update service type Direct
    if len(network_audit['configuration']) == 0:
        network_audit['configuration'].append('direct')
        
    return network_audit

# Extract BGP LAN prefix
def get_bgp_prefix(device_config, connection, network_audit):
    """Extract BGP LAN prefix"""
    
    peer_config = []
    import_policies = ['C-CUST-IN', 'C-CUST-P-A-IN', 'C-CUST-P-I-IN']
    customer_import = []
    customer_import_policy = None
    prefixes = set()
    
    # Extract BGP prefixes
    if network_audit['bgp_peer_v4'] != 'Unknown':
        
        lines = device_config['config_bgp_neighbors'].splitlines()
        
        # Pull matching peer config into temp list
        for line in lines:
            if network_audit['bgp_peer_v4'] in line:
                peer_config.append(line)
            
        # Extract customer import policies
        for line in peer_config:
            parts = line.split()
            if 'import' in parts:
                import_index = parts.index('import') + 1
                customer_import.append(parts[import_index])
                
        # Extract customer import policy to get LAN prefix
        for policy in customer_import:
            if policy not in import_policies:
                customer_import_policy = policy
    
    # Get policy statement config
    print(f'Running command show configuration policy-options policy-statement {customer_import_policy} | display set  ...')
    bgp_policy_config = connection.send_command(f'show configuration policy-options policy-statement {customer_import_policy} | display set')
    
    lines = bgp_policy_config.splitlines()
    
    # Get prefix from config
    for line in lines:
        if 'route-filter' in line:
            parts = line.split()
            prefix_index = parts.index('route-filter') + 1
            prefixes.add(parts[prefix_index])
            
    # Check if prefix is v4 or v6
    for prefix in prefixes:
        net = ipaddress.ip_network(prefix)
        if net.version == 4:
            network_audit['v4_bgp_prefixes'].add(str(prefix))
        elif net.version == 6:
            network_audit['v6_bgp_prefixes'].add(str(prefix))
            
    return network_audit        
                                
def disconnect_session(creds, connection):
    """Disconnect SSH session"""
    
    connection.disconnect()
    print(f"Session to {creds['host']} disconnected")
    

def print_audit(network_audit):
    """Clean up and print audit output"""
    
    # Normalise values before printing
    keys_list = list(network_audit.keys())
    
    for k in keys_list:
        v = network_audit[k]
    
        # String Unknown > N/A
        if isinstance(v, str):
            if v == 'Unknown':
                network_audit[k] = 'N/A'
            continue
    
        # None > N/A
        if v is None:
            network_audit[k] = 'N/A'
            continue
        
        # List: Empty > 'N/A', or create comma separated string
        if isinstance(v, list):
            if len(v) == 0:
                network_audit[k] = 'N/A'
            else:
                parts = []
                for item in v:
                    parts.append(str(item))
                joined = ''
                for index in range(len(parts)):
                    # Set 1st value to item
                    if index == 0:
                        joined = parts[index]
                    else:
                        # Comma separate the rest of the items
                        joined = joined + ', ' + parts[index]
                    network_audit[k] = joined
            continue
        
        # Set: Empty > 'N/A', or create comma separated string
        if isinstance(v, set):
            if len(v) == 0:
                network_audit[k] = 'N/A'
            else:
                parts = []
                for item in v:
                    parts.append(str(item))
                joined = ''
                for index in range(len(parts)):
                    # Set 1st value to item
                    if index == 0:
                        joined = parts[index]
                    else:
                        # Comma separate the rest of the items
                        joined = joined + ', ' + parts[index]
                    network_audit[k] = joined
            continue
        
        # Other types > convert to string
        if not isinstance(v, str):
            network_audit[k] = str(v)
                         
    print('\n-------- Network Audit ----------- ')
    for k, v in network_audit.items():
        print(f'{k.ljust(20)}: {v}')

def main():
    """Top level orchestration"""
    try: # Get device and port to audit from txt file
        device, port = get_audit_targets()
        print(f'Loaded audit target: {device} {port}...')
    except FileNotFoundError:
        print("'Error: 'to_audit.txt' file could not be found. Check and try again.")
        sys.exit(1)
    except ValueError as e:
        print(f'ValueError: {e}')
        sys.exit(1)
        
    try: # Get device credentials for SSH
        creds = get_device_creds(device)
    except KeyboardInterrupt:
        print('Error: Input cancelled by user...')
        sys.exit(1)
    except ValueError:
        print('Error: Value Error...')
        sys.exit(1)
    
    # Initialise connection
    connection = None
    
    try: # Establish SSH session
        connection = establish_session(creds)
    except AuthenticationException:
        print('Authentication failed. Goodbye...')
        sys.exit(1)
    except NetMikoTimeoutException:
        print('Connection timed out. Goodbye...')
        sys.exit(1)
    except SSHException:
        print('SSH issue ocurred. Goodbye...')
        sys.exit(1)
        
    # Session work once connection is made
    try:
        # Check interface exists before attempting to pull config
        if not check_interface_exists(connection, port):
            print(f"Error: Port {port} not found. Check audit source file and run again...")
            
            # Exit function if port does not exist
            return
        # Send commands to get various configs
        device_config = get_config(connection, port)
        
        # Validate contents of device_config before passing to audit
        validate_required_outputs(device_config)
        print('Validation check complete. Required keys are present and values are good...')
        
        # Proceed with audits
        network_audit = audit_interface(device_config, device)
        print('Interface config check complete...')
        
        # Audit static routes
        audit_static_routes(device_config, network_audit)
        print('Static route config check complete...')
        
        # Audit BGP peers
        audit_bgp(device_config, network_audit)
        print('BGP peer config check complete...')
        
        if network_audit['bgp_peer_v4'] != 'Unknown' or network_audit['bgp_peer_v6'] != 'Unknown':
            # Only attempt to pull LAN prefix if BGP peer is a valid IP address
            get_bgp_prefix(device_config, connection, network_audit)
            print('Getting BGP prefix information...')
        
        # Final cleanup and print audit result
        print_audit(network_audit)
        
    except RuntimeError as e:
        print(f'RuntimeError: {e}')
        sys.exit(1)
    except Exception as e:
        print(f'Unexpected {type(e).__name__}: {e}')
        sys.exit(1)
    finally:
        if connection is not None:
            print('Disconnecting SSH session...')
            disconnect_session(creds, connection)
         
if __name__ == "__main__":
    main()

