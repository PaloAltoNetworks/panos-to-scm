import logging
import re
from ipaddress import ip_network, ip_address
from . import map_port

class CiscoParser:
    def __init__(self, file_path): # Initialize the CiscoParser class
        self.file_path = file_path # Set the file_path
        self.logger = logging.getLogger(__name__) # Get the logger
        self.data = { # Initialize the data dictionary
            'Address': [], # Initialize the Address list
            'AddressGroup': [], # Initialize the AddressGroup list
            'Service': [], # Initialize the Service list
            'ServiceGroup': [], # Initialize the ServiceGroup list
            'Tag': [], # Initialize the Tag list
            'Unsupported': [] # Initialize the Unsupported list
        }
        self.addresses = set()  # Track known addresses and address groups
        self.services = set()  # Track known services and service groups
        self.single_service_groups = []  # Track single-member service groups
        self.unsupported_services = {
            'icmp', 'PING.icmp_v4', 'obj_icmp_echo-reply', 'obj_icmp_time-exceeded',
            'obj_icmp_echo', 'obj_icmp_unreachable', 'echo-reply', 'time-exceeded',
            'unreachable', 'echo', 'destination-unreachable', 'icmp_v4', 'icmp_v6',
            'gre', 'esp', 'ah'
        } # Track unsupported services and service groups to filter out
        self.unresolved_groups = {}  # Track unresolved groups and their members for later resolution
        self.service_name_mapping = {}  # Map original service names to new names for service groups
        self.processed_services = set()  # Track processed services and service groups to avoid duplicates
        self.processed_tags = set()  # Track processed tags to avoid duplicates
        self.hostname = ''  # Track device hostname for tag creation

    def parse(self): # Parse the Cisco file
        try: # Try block to catch exceptions and log them if any occurs during the parsing process
            with open(self.file_path, 'r') as file: # Open the file in read mode as file
                self.lines = file.readlines() # Read the lines of the file and set it as self.lines

            self._parse_lines(self.lines) # Call the _parse_lines method with self.lines as argument to parse the lines of the file

            # Process single-service groups and filter unsupported services after parsing
            self._process_single_service_groups() # Call the _process_single_service_groups method to process single-service service-groups
            self._filter_unsupported_services() # Call the _filter_unsupported_services method to filter out unsupported services

            # Resolve groups after filtering
            self._resolve_groups() # Call the _resolve_groups method to resolve groups after filtering the unsupported services and service groups from the data

            # Generate security pre-rules entries
            self.data['security_pre_rules'] = self._security_pre_rules_entries() # Call the _security_pre_rules_entries method to generate security pre-rules entries and set it as 'security_pre_rules' in the data dictionary
        except Exception as e:
            self.logger.error(f'Error parsing Cisco file: {e}', exc_info=True) # Log the error if any occurs during the parsing process with the exception information

    def _parse_lines(self, lines): # Parse the lines
        current_object = None # Initialize current_object as None
        current_type = None # Initialize current_type as None

        for line in lines: # Loop through the lines of the file to parse each line
            line = line.strip() # Strip the line to remove any leading or trailing whitespaces
            # self.logger.debug(f'Processing line: {line}') # Log the line being processed

            if line.startswith('hostname'): # Check if the line starts with 'hostname' to get the hostname of the device for tag creation
                parts = line.split() # Split the line
                name = parts[1] # Get the hostname
                self._create_tag(name, 'Red-Orange') # Call the _create_tag method with the hostname and 'Red-Orange' as arguments to create a tag
                self.hostname = name # Set the hostname as the name
            elif line.startswith('access-list'):
                parts = line.split()
                if 'eq' in parts:
                    eq_index = parts.index('eq')
                    if eq_index + 1 < len(parts):
                        port = map_port(parts[eq_index + 1])
                        protocol = 'tcp' if 'tcp' in parts else 'udp'
                        self._create_service(protocol, port)
            elif line.startswith('object network'):
                if current_object:
                    self._save_current_object(current_object, current_type)
                current_object = {'name': line.split()[-1], 'type': 'network'}
                current_type = 'address'
            elif line.startswith('object-group network'):
                if current_object:
                    self._save_current_object(current_object, current_type)
                current_object = {'name': line.split()[-1], 'type': 'network-group', 'members': []}
                current_type = 'AddressGroup'
            elif line.startswith('object service'):
                if current_object:
                    self._save_current_object(current_object, current_type)
                current_object = {'name': line.split()[2], 'type': 'Service'}
                current_type = 'Service'
            elif line.startswith('object-group service'):
                if current_object:
                    self._save_current_object(current_object, current_type)
                parts = line.split()

                # Determine if protocol is present on the same line (Firepower) or not (ASA)
                if len(parts) >= 4 and parts[-1] in ['tcp', 'udp', 'ip']:
                    # Firepower format
                    current_object = {'name': parts[-2], 'type': 'service-group', 'protocol': parts[-1], 'members': []}
                else:
                    # ASA format (protocol might be on the next line)
                    current_object = {'name': parts[-1], 'type': 'service-group', 'protocol': None, 'members': []}
                
                current_type = 'ServiceGroup'
            elif line.startswith('service-object'):
                if current_object and current_object['type'] == 'service-group':
                    parts = line.split()
                    if parts[1] == 'object':  # Handle the case where service-object refers to another object
                        obj_name = self._sanitize_name(parts[2])
                        current_object['members'].append(obj_name)
                        self.service_name_mapping[current_object['name']] = obj_name
                    elif len(parts) >= 5:  # Handle ASA case where protocol is not in first line
                        protocol = parts[1].lower()
                        if parts[2] == 'destination' and parts[3] == 'eq':
                            port = map_port(parts[4])
                            service_name = self._sanitize_name(f'{protocol.upper()}-{port}')
                            if service_name not in self.processed_services:
                                self._add_service(port, protocol, service_name)
                            current_object['members'].append(service_name)
                            self.service_name_mapping[current_object['name']] = service_name
                    elif current_object['protocol']:  # Handle Firepower case where protocol is in the first line
                        protocol = current_object['protocol'].lower()
                        if len(parts) >= 4 and parts[1] == 'destination' and parts[2] == 'eq':
                            port = map_port(parts[3])
                            service_name = self._sanitize_name(f'{protocol.upper()}-{port}')
                            if service_name not in self.processed_services:
                                self._add_service(port, protocol, service_name)
                            current_object['members'].append(service_name)
                            self.service_name_mapping[current_object['name']] = service_name
            elif line.startswith('description'):
                if current_object:
                    current_object['description'] = line.split(' ', 1)[1]
            elif line.startswith('subnet'):
                if current_object:
                    parts = line.split()
                    try:
                        subnet = ip_network(f'{parts[1]}/{self._netmask_to_cidr(parts[2])}')
                        current_object['ip_netmask'] = str(subnet)
                    except ValueError as e:
                        self.logger.error(f'Error parsing subnet: {e}')
                        continue
            elif line.startswith('host'):
                if current_object:
                    current_object['ip_netmask'] = line.split()[-1]
                    self.logger.debug(f'Parsed host: {current_object}')
            elif line.startswith('range'):
                if current_object:
                    parts = line.split()
                    range_start = ip_address(parts[1])
                    range_end = ip_address(parts[2])
                    current_object['ip_range'] = f'{range_start}-{range_end}'
            elif line.startswith('fqdn'):
                if current_object:
                    parts = line.split()
                    current_object['fqdn'] = parts[-1]
                    self.logger.debug(f'Parsed fqdn: {current_object}')
            elif line.startswith('network-object'):
                if current_object:
                    parts = line.split()
                    if parts[1] == 'object':
                        obj_name = self._sanitize_name(parts[2])
                        current_object['members'].append(obj_name)
                        self.logger.debug(f'Added network-object member {obj_name} to {current_object["name"]}')
                    elif parts[1] == 'host':
                        ip_netmask = parts[2]
                        name = self._sanitize_name(f'H-{ip_netmask}')
                        if ip_netmask not in self.addresses:
                            self.addresses.add(ip_netmask)
                            self.data['Address'].append({'name': name, 'ip_netmask': ip_netmask})
                            self.logger.debug(f'1 Added new address: {name} with ip-netmask: {ip_netmask}')
                        current_object['members'].append(name)
                    else:
                        if len(parts) == 3:
                            try:
                                cidr = self._netmask_to_cidr(parts[2])
                                ip_netmask = f'{parts[1]}/{cidr}'
                                if cidr == 32 or cidr == 128:
                                    name = self._sanitize_name(f'H-{parts[1]}')
                                    self.logger.debug(f'1 Network-object {name} without netmask: {ip_netmask}')
                                else:
                                    name = self._sanitize_name(f'N-{parts[1]}-{cidr}')
                                    self.logger.debug(f'1 Network-object {name} with netmask: {ip_netmask}')
                            except ValueError as e:
                                self.logger.error(f'Error parsing network-object: {e}')
                                continue
                        else:
                            ip_netmask = parts[1]
                            name = self._sanitize_name(f'H-{ip_netmask}')
                        if ip_netmask not in self.addresses:
                            self.addresses.add(ip_netmask)
                            self.data['Address'].append({'name': name, 'ip_netmask': ip_netmask})
                            self.logger.debug(f'2 Added new address: {name} with ip-netmask: {ip_netmask}')
                        current_object['members'].append(name)
            elif line.startswith('port-object'):
                if current_object and current_object['type'] == 'service-group':
                    parts = line.split()
                    if parts[1] == 'range':
                        port = f'{parts[2]}-{parts[3]}'
                    elif parts[1] == 'eq':
                        port = map_port(parts[2])
                    else:
                        port = map_port(parts[-1])
                    service_name = self._sanitize_name(f'{current_object["protocol"].upper()}-{port}')
                    if service_name not in self.processed_services:
                        self._add_service(port, current_object['protocol'], service_name)
                    current_object['members'].append(service_name)
                    self.service_name_mapping[current_object['name']] = service_name
            elif line.startswith('group-object'):
                if current_object:
                    obj_name = self._sanitize_name(line.split()[-1])
                    mapped_name = self.service_name_mapping.get(obj_name, obj_name)
                    current_object['members'].append(mapped_name)
                    self.logger.debug(f'Added group-object member {mapped_name} to {current_object["name"]}')
                    if current_type == 'AddressGroup':
                        self.unresolved_groups.setdefault(current_object['name'], []).append(obj_name)
            elif line.startswith('service tcp destination eq') or line.startswith('service udp destination eq'):
                if current_object and current_object.get('type') == 'Service':
                    parts = line.split()
                    port = map_port(parts[-1])
                    protocol = 'tcp' if 'tcp' in line else 'udp'
                    current_object['protocol'] = {protocol: {'port': port}}
                    self.logger.debug(f'Parsed service: {current_object}')
            elif 'advanced permit' in line and 'rule-id' in line:
                parts = line.split()
                if 'eq' in parts:
                    eq_index = parts.index('eq')
                    if eq_index + 1 < len(parts):
                        protocol = parts[4].upper()
                        port = map_port(parts[eq_index + 1])
                        service_name = f'{protocol}-{port}'
                        if service_name not in self.processed_services:
                            self._create_service(protocol, port)
                if len(parts) >= 6:
                    destination_ip = parts[-3]
                    netmask = parts[-2]
                    try:
                        cidr = self._netmask_to_cidr(netmask)
                        ip_netmask = f'{destination_ip}/{self._netmask_to_cidr(netmask)}'
                        name = self._sanitize_name(f'N-{destination_ip}-{cidr}')
                        if ip_netmask not in self.addresses:
                            self.addresses.add(ip_netmask)
                            self.data['Address'].append({'name': name, 'ip_netmask': ip_netmask})
                            self.logger.debug(f'3 Added new address: {name} with ip-netmask: {ip_netmask}')
                    except ValueError as e:
                        self.logger.error(f'Error parsing IP Netmask: {e}')

        if current_object:
            self._save_current_object(current_object, current_type)

    def _add_service(self, port, protocol, service_name):
        if service_name not in self.processed_services:
            new_service = {
                'name': service_name,
                'protocol': {protocol: {'port': port}}
            }
            self.data['Service'].append(new_service)
            self.processed_services.add(service_name)
            self.logger.debug(f'Added new service: {new_service}')

    def _save_current_object(self, obj, obj_type):
        if obj_type == 'address':
            if 'ip_netmask' in obj or 'ip_range' in obj or 'fqdn' in obj:
                obj['name'] = self._sanitize_name(obj['name'])
                self.data['Address'].append(obj)
        elif obj_type == 'AddressGroup':
            obj['name'] = self._sanitize_name(obj['name'])
            obj['static'] = obj.pop('members', [])
            self.data['AddressGroup'].append(obj)
        elif obj_type == 'Service':
            protocol = list(obj['protocol'].keys())[0]
            port = obj['protocol'][protocol]['port']
            obj['name'] = self._sanitize_name(f'{protocol.upper()}-{port}')
            self.data['Service'].append(obj)
            self.service_name_mapping[obj['name']] = obj['name']
        elif obj_type == 'ServiceGroup':
            self._save_service_group(obj)

    def _save_service_group(self, obj):
        if 'members' not in obj:
            obj['members'] = []
        if len(obj['members']) == 1:
            single_member = obj['members'][0]
            self.service_name_mapping[obj['name']] = single_member
        else:
            obj['members'] = list(set([self._get_correct_obj_name(member) for member in obj['members']]))
            self.data['ServiceGroup'].append(obj)

    def _get_correct_obj_name(self, member):
        return self.service_name_mapping.get(member, member)

    def _resolve_groups(self):
        passes = 0
        while self.unresolved_groups and passes < 10:
            self.logger.debug(f'Resolving groups, pass {passes + 1}')
            resolved_in_pass = []
            for group, members in self.unresolved_groups.items():
                if all(member in self.addresses for member in members):
                    self.logger.debug(f'Resolving group {group} with members: {members}')
                    self.data['AddressGroup'].append({'name': group, 'static': members})
                    resolved_in_pass.append(group)
                    for member in members:
                        self.addresses.add(member)

            for group in resolved_in_pass:
                self.unresolved_groups.pop(group)

            passes += 1

        if self.unresolved_groups:
            unresolved_list = list(self.unresolved_groups.keys())
            self.logger.debug(f'Unresolved groups after all passes: {unresolved_list}')
            for group in unresolved_list:
                self.logger.debug(f"Group '{group}' unresolved members: {self.unresolved_groups[group]}")

    def _process_single_service_groups(self):
        for service in self.single_service_groups:
            port = service['protocol'].get(list(service['protocol'].keys())[0]).get('port')
            if port.isdigit() or map_port(port) != port:
                self.data['Service'].append(service)
            else:
                self.data['ServiceGroup'].append(service)

    def _filter_unsupported_services(self):
        # Filter out unsupported services from the service groups
        filtered_service_groups = []
        for service_group in self.data['ServiceGroup']:
            if 'members' in service_group:
                filtered_members = [member for member in service_group['members'] if member not in self.unsupported_services]
                if filtered_members:
                    service_group['members'] = filtered_members
                    filtered_service_groups.append(service_group)
                else:
                    self.logger.debug(f"Skipping service group '{service_group['name']}' as all members are unsupported.")
        self.data['ServiceGroup'] = filtered_service_groups

        # Filter out unsupported services from the services list
        filtered_services = [service for service in self.data['Service'] if service['name'] not in self.unsupported_services]
        self.data['Service'] = filtered_services

        # Ensure service_name_mapping does not contain unsupported services
        self.service_name_mapping = {k: v for k, v in self.service_name_mapping.items() if v not in self.unsupported_services}

    def _netmask_to_cidr(self, netmask):
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def _sanitize_name(self, name):
        # Replace disallowed characters with underscore
        name = re.sub(r'[:\s/\\(),;=\'"&!@#$%^*+?<>{}~`]', '_', name).strip('_')
        # Remove consecutive underscores
        name = re.sub(r'__+', '_', name)
        # Check if the name is 'any' and replace it with 'any-grp' for address groups
        if name == 'any':
            return 'any-grp'
        return name[:63]

    def _create_service(self, protocol, port):
        service_name = f'{protocol.upper()}-{port}'
        if service_name not in self.processed_services:
            new_service = {
                'name': service_name,
                'protocol': {protocol.lower(): {'port': port}}
            }
            self.data['Service'].append(new_service)
            self.processed_services.add(service_name)
            self.service_name_mapping[service_name] = service_name
            self.logger.debug(f'Added new service: {new_service}')
        return service_name

    def _create_tag(self, name, color):
        tag_name = name.upper()
        if not color:
            color = 'Red'
        if tag_name not in self.processed_tags:
            new_tag = {
                'name': tag_name,
                'color': color
            }
            self.data['Tag'].append(new_tag)
            self.processed_tags.add(tag_name)
            self.logger.debug(f'Added new tag: {new_tag}')
        return tag_name

    def _initialize_rule(self):
        return {
            'name': '',
            'description': '',
            'tag': set(),
            'from': set(),
            'source': set(),
            'negate_source': False,
            'source_user': ['any'],
            'source_hip': ['any'],
            'to': set(),
            'destination': set(),
            'negate_destination': False,
            'destination_hip': ['any'],
            'application': set(['any']),
            'service': set(),
            'category': ['any'],
            'disabled': False,
            'log_setting': 'Cortex Data Lake',
            'action': None,
            'profile_setting': {'group': ['best-practice']},
            'schedule': None
        }

    def _security_pre_rules_entries(self):
        security_rules = {}
        config_type = self._detect_config_type()

        current_rule_id = None
        current_rule = None
        rule_count = 0

        for line in self.lines:
            line = line.strip()
            parts = line.split()

            if config_type == 'firepower' and line.startswith('access-list'):
                if 'remark' in parts:
                    rule_id_index = parts.index('rule-id') + 1
                    current_rule_id = parts[rule_id_index]
                    remark = ' '.join(parts[parts.index('remark') + 2:])
                    if 'bgp-bypass' in remark.lower() or 'DEFAULT TUNNEL ACTION RULE' in remark.upper():
                        security_rules.pop(current_rule_id, None)
                        current_rule_id = None
                        current_rule = None
                        continue
                    if 'ACCESS POLICY:' in remark:
                        description = remark
                        if current_rule_id not in security_rules:
                            security_rules[current_rule_id] = self._initialize_rule()
                        security_rules[current_rule_id]['description'] = description
                    elif 'L7 RULE:' in remark or 'L4 RULE:' in remark or 'RULE:' in remark:
                        rule_name = self._sanitize_rule_name(remark.split(': ')[-1])
                        if current_rule_id not in security_rules:
                            security_rules[current_rule_id] = self._initialize_rule()
                        security_rules[current_rule_id]['name'] = rule_name
                    current_rule = security_rules[current_rule_id]
                elif 'advanced' in parts and current_rule_id and current_rule:
                    self._parse_ngfw_acl(parts, current_rule, current_rule_id, security_rules)
            
            elif config_type == 'asa' and line.startswith('access-list'):
                if 'extended' in parts:
                    rule_count += 1
                    rule_name = f'Rule-{rule_count}'
                    current_rule = security_rules[rule_name] = self._initialize_rule()
                    current_rule['name'] = rule_name
                    description = (f'Rule {rule_count} from ASA configuration')
                    current_rule['description'] = description
                    self._parse_asa_acl(parts, current_rule, rule_name, security_rules)

        consolidated_rules = self._consolidate_rules(security_rules)
        self.logger.debug(f'FOUND THESE SECURITY PRE RULES: {consolidated_rules}')
        return consolidated_rules

    def _parse_asa_acl(self, parts, current_rule, rule_name, security_rules):
        self.logger.debug(f"Parsing ASA line for rule_name {rule_name}")
        action = 'allow' if 'permit' in parts else 'deny'
        current_rule['action'] = action

        from_zone, to_zone, source, destination, protocol = None, None, None, None, None
        i = 0
        while i < len(parts):
            part = parts[i]
            
            if part == 'object-group':
                if protocol is None:
                    protocol = self._get_correct_obj_name(parts[i + 1])
                    if protocol.lower() not in ['tcp', 'udp', 'ip']:
                        tag_name = f'REVIEW-{self.hostname}'
                        tag = self._create_tag(tag_name, 'Red')

                        # Create a new rule for APP-ID
                        app_rule = self._initialize_rule()
                        app_rule.update(current_rule)
                        app_rule['name'] = self._sanitize_rule_name(f"{current_rule['name']}-APP")
                        app_rule['application'] = set(['icmp', 'ping'])
                        app_rule['service'] = set(['application-default'])
                        app_rule['tag'].add(tag)

                        # Set from_zone and to_zone for the APP-ID rule
                        if from_zone:
                            app_rule['from'].add(from_zone)
                        if to_zone:
                            app_rule['to'].add(to_zone)

                        # Add the APP-ID rule to security_rules
                        app_rule_id = f"{rule_name}-APP-ID"
                        security_rules[app_rule_id] = app_rule

                        # Reset the current rule for other services
                        current_rule['application'] = set(['any'])
                        current_rule['service'] = set()
                        current_rule['tag'].add(tag)
                    else:
                        current_rule['service'].add(protocol)
                    i += 2
                elif not source:
                    source = self._get_correct_obj_name(parts[i + 1])
                    i += 2
                elif not destination:
                    destination = self._get_correct_obj_name(parts[i + 1])
                    i += 2
                else:
                    service_name = self._get_correct_obj_name(parts[i + 1])
                    current_rule['service'].add(service_name)
                    i += 2
            elif part == 'host':
                if i + 1 < len(parts):
                    address_name = self._add_or_get_address(parts[i + 1], '255.255.255.255')
                    if not destination:
                        destination = address_name
                    i += 2
                else:
                    i += 1
            elif re.match(r'\d+\.\d+\.\d+\.\d+', part):
                if i + 1 < len(parts) and re.match(r'\d+\.\d+\.\d+\.\d+', parts[i + 1]):
                    ip = part
                    netmask = parts[i + 1]
                    address_name = self._add_or_get_address(ip, netmask)
                    if not source:
                        source = address_name
                    elif not destination:
                        destination = address_name
                    i += 2
                else:
                    i += 1
            elif part in ['tcp', 'udp']:
                protocol = part.upper()
                if i + 1 < len(parts) and parts[i + 1] == 'eq':
                    port = map_port(parts[i + 2])
                    service_name = f"{protocol}-{port}"
                    current_rule['service'].add(service_name)
                    i += 3
                else:
                    i += 1
            elif part == 'eq':
                if protocol:
                    port = map_port(parts[i + 1])
                    service_name = f"{protocol}-{port}"
                    current_rule['service'].add(service_name)
                    i += 2
                else:
                    i += 1
            elif part == 'object':
                if not source:
                    source = parts[i + 1]
                elif not destination:
                    destination = parts[i + 1]
                i += 2
            elif part in ['any', 'any4', 'any6']:
                if not source:
                    source = 'any'
                elif not destination:
                    destination = 'any'
                i += 1
            else:
                i += 1

        # Set from_zone based on the ACL name
        acl_name = parts[1]  # Assuming the ACL name is the second part of the line
        from_zone = self._get_zone_from_acl(acl_name)
        current_rule['from'].add(from_zone)

        # Set to_zone as 'any'
        current_rule['to'].add('any')

        if source:
            current_rule['source'].add(source)
        if destination:
            current_rule['destination'].add(destination)
        
        self.logger.debug(f"After parsing ASA line for rule_name {rule_name}. current_rule: {current_rule}")

    def _get_zone_from_acl(self, acl_name):
        # Dictionary to store the mapping of ACL names to zones
        self.acl_to_zone_map = getattr(self, 'acl_to_zone_map', {})

        # If the mapping is already in the dictionary, return it
        if acl_name in self.acl_to_zone_map:
            return self.acl_to_zone_map[acl_name]

        # If not, we need to parse the configuration to find the mapping
        for line in self.lines:
            if line.startswith('access-group'):
                parts = line.split()
                if len(parts) >= 5 and parts[1] == acl_name and parts[2] == 'in' and parts[3] == 'interface':
                    zone = parts[4]
                    self.acl_to_zone_map[acl_name] = zone
                    return zone

        # If we couldn't find a mapping, use the ACL name as the zone
        self.logger.warning(f"Couldn't find zone mapping for ACL '{acl_name}'. Using ACL name as zone.")
        self.acl_to_zone_map[acl_name] = acl_name
        return acl_name

    def _parse_ngfw_acl(self, parts, current_rule, current_rule_id, security_rules):
        self.logger.debug(f"Parsing advanced line for rule_id {current_rule_id}. current_rule['name']: {current_rule.get('name')}") # Log the current rule id and name
        action = 'allow' if 'permit' in parts else 'deny' # Set the action as 'allow' if 'permit' is in parts else 'deny'
        current_rule['action'] = action # Set the action of the current rule

        from_zone, to_zone, source, destination, protocol = None, None, None, None, None # Initialize from_zone, to_zone, source, destination, protocol as None
        i = 0 # Initialize i as 0
        while i < len(parts): # Loop through the parts
            part = parts[i] # Get the part
            if part == 'ifc': # Check if part is 'ifc'
                if not from_zone: # Check if from_zone is not set
                    from_zone = parts[i + 1] # Set from_zone as the next part
                elif not to_zone: # Check if to_zone is not set
                    to_zone = parts[i + 1] # Set to_zone as the next part
                i += 2 # Increment i by 2
            elif part == 'object-group': # Check if part is 'object-group'
                if protocol is None: # Check if protocol is None
                    protocol = self._get_correct_obj_name(parts[i + 1]) # Call the _get_correct_obj_name method
                    if protocol.lower() not in ['tcp', 'udp', 'ip']: # Check if protocol is not 'tcp', 'udp', 'ip'
                        tag_name = f'REVIEW-{self.hostname}' # Set tag_name as f'REVIEW-{self.hostname}'
                        tag = self._create_tag(tag_name, 'Red') # Call the _create_tag method

                        # Create a new rule for APP-ID
                        app_rule = self._initialize_rule() # Initialize a new rule
                        app_rule.update(current_rule) # Update the new rule with the current rule
                        app_rule['name'] = self._sanitize_rule_name(f"{current_rule['name']}-APP")
                        app_rule['application'] = set(['icmp', 'ping']) # Set the application as set(['icmp', 'ping'])
                        app_rule['service'] = set(['application-default']) # Set the service as set(['application-default'])
                        app_rule['tag'].add(tag) # Add the tag to the tag

                        # Set from_zone and to_zone for the APP-ID rule
                        if from_zone: # Check if from_zone is set
                            app_rule['from'].add(from_zone) # Add from_zone to the 'from'
                        if to_zone: # Check if to_zone is set
                            app_rule['to'].add(to_zone) # Add to_zone to the 'to'

                        # Add the APP-ID rule to security_rules
                        app_rule_id = f"{current_rule_id}-APP-ID" # Set app_rule_id as f"{current_rule_id}-APP-ID"
                        security_rules[app_rule_id] = app_rule # Add the app_rule to security_rules

                        # Reset the current rule for other services
                        current_rule['application'] = set(['any']) # Set the application as set(['any'])
                        current_rule['service'] = set() # Set the service as set()
                        current_rule['tag'].add(tag) # Add the tag to the tag
                    else:
                        current_rule['service'].add(protocol) # Add the protocol to the service
                    i += 2 # Increment i by 2
                elif not source: # Check if source is not set
                    source = self._get_correct_obj_name(parts[i + 1]) # Call the _get_correct_obj_name method
                    i += 2
                elif not destination:
                    destination = self._get_correct_obj_name(parts[i + 1]) # Call the _get_correct_obj_name method
                    i += 2
                else:
                    service_name = self._get_correct_obj_name(parts[i + 1]) # Call the _get_correct_obj_name method
                    current_rule['service'].add(service_name) # Add the service_name to the service
                    i += 2
            elif part == 'host': # Check if part is 'host'
                if i + 1 < len(parts): # Check if i + 1 is less than the length of parts
                    address_name = self._add_or_get_address(parts[i + 1], '255.255.255.255') # Call the _add_or_get_address method
                    if not destination: # Check if destination is not set
                        destination = address_name # Set destination as address_name
                    i += 2 # Increment i by 2
                else: # If i + 1 is not less than the length of parts
                    i += 1 # Increment i by 1
            elif re.match(r'\d+\.\d+\.\d+\.\d+', part):
                if i + 1 < len(parts) and re.match(r'\d+\.\d+\.\d+\.\d+', parts[i + 1]):
                    ip = part
                    netmask = parts[i + 1]
                    address_name = self._add_or_get_address(ip, netmask) # Call the _add_or_get_address method
                    if not source:
                        source = address_name
                    elif not destination:
                        destination = address_name
                    i += 2
                else:
                    i += 1
            elif part in ['tcp', 'udp']: # Check if part is 'tcp' or 'udp'
                protocol = part.upper() # Set protocol as part.upper() for naming convention 'TCP-<port>', 'UDP-<port>'
                if i + 1 < len(parts) and parts[i + 1] == 'eq': # Check if i + 1 is less than the length of parts and the next part is 'eq'
                    port = map_port(parts[i + 2]) # Call the map_port method with the next part as argument and set the result as port
                    service_name = f"{protocol}-{port}" # Set service_name as f"{protocol}-{port}"
                    current_rule['service'].add(service_name) # Add service_name to the service
                    i += 3 # Increment i by 3
                else: # If i + 1 is not less than the length of parts or the next part is not 'eq'
                    i += 1 # Increment i by 1
            elif part == 'eq': # Check if part is 'eq'
                if protocol: # Check if protocol is set
                    port = map_port(parts[i + 1]) # Call the map_port method with the next part as argument and set the result as port
                    service_name = f"{protocol}-{port}" # Set service_name as f"{protocol}-{port}"
                    current_rule['service'].add(service_name) # Add service_name to the service
                    i += 2 # Increment i by 2
                else: # If protocol is not set
                    i += 1 # Increment i by 1
            elif part == 'object': # Check if part is 'object'
                if not source: # Check if source is not set
                    source = parts[i + 1] # Set source as the next part
                elif not destination: # Check if destination is not set
                    destination = parts[i + 1] # Set destination as the next part
                i += 2 # Increment i by 2
            elif part == 'any' or part == 'any4' or part == 'any6': # Check if part is 'any' or 'any4' or 'any6'
                if not source: # Check if source is not set
                    source = 'any' # Set source as 'any'
                elif not destination: # Check if destination is not set
                    destination = 'any' # Set destination as 'any'
                i += 1 # Increment i by 1
            else: # If part is not any of the above
                i += 1 # Increment i by 1

        if from_zone: # Check if from_zone is set
            current_rule['from'].add(from_zone) # Add from_zone to the 'from'
        if to_zone: # Check if to_zone is set
            current_rule['to'].add(to_zone) # Add to_zone to the 'to'
        if source: # Check if source is set
            current_rule['source'].add(source) # Add source to the source
        if destination: # Check if destination is set
            current_rule['destination'].add(destination) # Add destination to the destination
        self.logger.debug(f"After parsing advanced line for rule_id {current_rule_id}. current_rule['name']: {current_rule.get('name')}") # Log the current rule id and name

    def _sanitize_rule_name(self, name):
        name = self._sanitize_name(name) # Call the _sanitize_name method
        rule_name_count = getattr(self, '_rule_name_count', {}) # Get the _rule_name_count attribute
        if name in rule_name_count:
            rule_name_count[name] += 1
            self._rule_name_count = rule_name_count  # Update the instance variable
            return f'{name}-{rule_name_count[name]}'
        rule_name_count[name] = 1
        self._rule_name_count = rule_name_count  # Update the instance variable
        return name

    def _consolidate_rules(self, security_rules): # Consolidate the rules
        consolidated_rules = [] # Initialize consolidated_rules as an empty list
        for rule in security_rules.values(): # Loop through the values of security_rules
            rule['from'] = list(rule['from']) if rule['from'] else ['any'] # Set 'from' as list(from) if from is not empty else ['any']
            rule['to'] = list(rule['to']) if rule['to'] else ['any'] # Set 'to' as list(to) if to is not empty else ['any']
            rule['source'] = list(rule['source']) if rule['source'] else ['any'] # Set 'source' as list(source) if source is not empty else ['any']
            rule['destination'] = list(rule['destination']) if rule['destination'] else ['any'] # Set 'destination' as list(destination) if destination is not empty else ['any']
            rule['service'] = list(rule['service']) if rule['service'] else ['any'] # Set 'service' as list(service) if service is not empty else ['any']
            rule['application'] = list(rule['application']) if rule['application'] else ['any'] # Set 'application' as list(application) if application is not empty else ['any']
            rule['tag'] = list(rule['tag']) if rule['tag'] else [] # Set 'tag' as list(tag) if tag is not empty else []
            rule['destination'] = [dest for dest in rule['destination'] if not dest.startswith(('TCP-', 'UDP-', 'IP-'))] # Filter out destination that starts with 'TCP-', 'UDP-', 'IP-'
            if not rule['destination']: # Check if destination is empty
                rule['destination'] = ['any'] # Set destination as ['any']
            consolidated_rules.append(rule) # Append the rule to consolidated_rules
        return consolidated_rules # Return consolidated_rules

    def _detect_config_type(self): # Detect the config type for the device
        for line in self.lines:  # Loop through the lines
            if line.startswith('NGFW Version'):  # Check if the line starts with 'NGFW Version'
                return 'firepower'  # Return 'firepower'
            elif line.startswith('ASA Version'):  # Check if the line starts with 'ASA Version'
                return 'asa' # Return 'asa'
        return 'unknown' # Return 'unknown'

    def _add_or_get_address(self, ip, netmask):
        cidr = self._netmask_to_cidr(netmask) # Call the _netmask_to_cidr method
        ip_netmask = f'{ip}/{cidr}' # Set ip_netmask as f'{ip}/{cidr}'
        if ip_netmask in self.addresses: # Check if ip_netmask is in addresses
            for addr in self.data['Address']: # Loop through the Address data
                if addr.get('ip_netmask') == ip_netmask or addr.get('fqdn') == ip or addr.get('ip_range') == ip: # Check if ip_netmask or fqdn or ip_range is in addr
                    return addr['name'] # Return the name of addr if ip_netmask or fqdn or ip_range is in addr

        if cidr == 32 or cidr == 128: # Check if cidr is 32 or 128
            name = self._sanitize_name(f'H-{ip}') # Set name as f'H-{ip}' 'H' stands for Host
        else: # If cidr is not 32 or 128
            name = self._sanitize_name(f'N-{ip}-{cidr}') # Set name as f'N-{ip}-{cidr}' 'N' stands for Network

        self.addresses.add(ip_netmask) # Add ip_netmask to addresses
        new_address = {'name': name, 'ip_netmask': ip_netmask} # Set new_address as {'name': name, 'ip_netmask': ip_netmask}
        self.data['Address'].append(new_address) # Append new_address to Address
        self.logger.debug(f'Added new address: {name} with ip-netmask: {ip_netmask}') # Log the new address
        return name # Return name

    def get_parsed_data(self): # Get the parsed data
        parsed_data = self.data.copy() # Copy the data
        parsed_data['security_post_rules'] = []  # Add empty security_post_rules
        parsed_data['app_override_pre_rules'] = []  # Add empty app_override_pre_rules
        parsed_data['app_override_post_rules'] = [] # Add empty app_override_post_rules
        parsed_data['decryption_pre_rules'] = [] # Add empty decryption_pre_rules
        parsed_data['decryption_post_rules'] = [] # Add empty decryption_post_rules
        parsed_data['nat_pre_rules'] = [] # Add empty nat_pre_rules
        parsed_data['nat_post_rules'] = [] # Add empty nat_post_rules
        self.logger.debug(f'Service name mapping: {self.service_name_mapping}') # Log the service name mapping
        return parsed_data # Return the parsed data