import logging
import re
from ipaddress import ip_network, ip_address
from . import map_port  # Import map_port from the __init__.py file

class CiscoParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.logger = logging.getLogger(__name__)
        self.data = {
            'Address': [],
            'AddressGroup': [],
            'Service': [],
            'ServiceGroup': [],
            'Tag': [],
            'Unsupported': []
        }
        self.addresses = set()  # Track known addresses
        self.services = set()  # Track known services
        self.single_service_groups = []  # Track single-member service groups
        self.unsupported_services = {
            'icmp', 'PING.icmp_v4', 'obj_icmp_echo-reply', 'obj_icmp_time-exceeded',
            'obj_icmp_echo', 'obj_icmp_unreachable', 'echo-reply', 'time-exceeded',
            'unreachable', 'echo', 'destination-unreachable', 'icmp_v4', 'icmp_v6',
            'gre', 'esp', 'ah'
        }
        self.unresolved_groups = {}  # Track unresolved groups and their members
        self.service_name_mapping = {}  # Map original service names to new names
        self.processed_services = set()  # Track processed services
        self.processed_tags = set()  # Track processed tags
        self.hostname = ''  # Track device hostname

    def parse(self):
        try:
            with open(self.file_path, 'r') as file:
                self.lines = file.readlines()
            self.parse_lines_first_pass(self.lines)
            self.process_single_service_groups()
            self.filter_unsupported_services()  # Ensure unsupported services are filtered
            self.resolve_groups()
            self.data['security_pre_rules'] = self._security_pre_rules_entries()
        except Exception as e:
            self.logger.error(f'Error parsing Cisco file: {e}', exc_info=True)

    def parse_lines_first_pass(self, lines):
        current_object = None
        current_type = None

        for line in lines:
            line = line.strip()
            self.logger.debug(f'Processing line: {line}')

            if line.startswith('hostname'):
                parts = line.split()
                name = parts[1]
                self.create_tag(name, 'Red-Orange')
                self.hostname = name
            elif line.startswith('access-list'):
                parts = line.split()
                if 'eq' in parts:
                    eq_index = parts.index('eq')
                    if eq_index + 1 < len(parts):
                        port = map_port(parts[eq_index + 1])
                        protocol = 'tcp' if 'tcp' in parts else 'udp'
                        self.create_service(protocol, port)
            elif line.startswith('object network'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                current_object = {'name': line.split()[-1], 'type': 'network'}
                current_type = 'address'
            elif line.startswith('object-group network'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                current_object = {'name': line.split()[-1], 'type': 'network-group', 'members': []}
                current_type = 'AddressGroup'
            elif line.startswith('object service'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                current_object = {'name': line.split()[2], 'type': 'Service'}
                current_type = 'Service'
            elif line.startswith('object-group service'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                parts = line.split()
                current_object = {'name': parts[-2], 'type': 'service-group', 'protocol': parts[-1], 'members': []}
                current_type = 'ServiceGroup'
            elif line.startswith('description'):
                if current_object:
                    current_object['description'] = line.split(' ', 1)[1]
            elif line.startswith('subnet'):
                if current_object:
                    parts = line.split()
                    try:
                        subnet = ip_network(f'{parts[1]}/{self.netmask_to_cidr(parts[2])}')
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
                        obj_name = self.sanitize_name(parts[2])
                        current_object['members'].append(obj_name)
                        self.logger.debug(f'Added network-object member {obj_name} to {current_object["name"]}')
                    elif parts[1] == 'host':
                        ip_netmask = parts[2]
                        name = self.sanitize_name(f'H-{ip_netmask}')
                        if ip_netmask not in self.addresses:
                            self.addresses.add(ip_netmask)
                            self.data['Address'].append({'name': name, 'ip_netmask': ip_netmask})
                            self.logger.debug(f'Added new address: {name} with ip-netmask: {ip_netmask}')
                        current_object['members'].append(name)
                    else:
                        if len(parts) == 3:
                            try:
                                cidr = self.netmask_to_cidr(parts[2])
                                ip_netmask = f'{parts[1]}/{cidr}'
                                name = self.sanitize_name(f'N-{parts[1]}-{cidr}')
                            except ValueError as e:
                                self.logger.error(f'Error parsing network-object: {e}')
                                continue
                        else:
                            ip_netmask = parts[1]
                            name = self.sanitize_name(f'H-{ip_netmask}')
                        if ip_netmask not in self.addresses:
                            self.addresses.add(ip_netmask)
                            self.data['Address'].append({'name': name, 'ip_netmask': ip_netmask})
                            self.logger.debug(f'Added new address: {name} with ip-netmask: {ip_netmask}')
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
                    service_name = self.sanitize_name(f'{current_object["protocol"].upper()}-{port}')
                    if service_name not in self.processed_services:
                        self.add_service(port, current_object['protocol'], service_name)
                    current_object['members'].append(service_name)
                    self.service_name_mapping[current_object['name']] = service_name
            elif line.startswith('group-object'):
                if current_object:
                    obj_name = self.sanitize_name(line.split()[-1])
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

        if current_object:
            self.save_current_object(current_object, current_type, first_pass=True)

    def _parse_hostname(self, line):
        parts = line.split()
        name = parts[1]
        self.create_tag(name, 'Red-Orange')
        self.hostname = name

    def _parse_access_list(self, line):
        parts = line.split()
        if 'eq' in parts:
            eq_index = parts.index('eq')
            if eq_index + 1 < len(parts):
                port = map_port(parts[eq_index + 1])
                protocol = 'tcp' if 'tcp' in parts else 'udp'
                self.create_service(protocol, port)

    def _start_new_object(self, current_object, line, obj_type, current_type):
        if current_object:
            self.save_current_object(current_object, current_type, first_pass=True)
        current_object = {'name': line.split()[-1], 'type': obj_type}
        if current_type in ['AddressGroup', 'ServiceGroup']:
            current_object['members'] = []
        if current_type == 'ServiceGroup':
            parts = line.split()
            if len(parts) >= 2:
                current_object['protocol'] = parts[-1]
        return current_object, current_type

    def _parse_subnet(self, line, current_object):
        parts = line.split()
        try:
            subnet = ip_network(f'{parts[1]}/{self.netmask_to_cidr(parts[2])}')
            current_object['ip_netmask'] = str(subnet)
        except ValueError as e:
            self.logger.error(f'Error parsing subnet: {e}')

    def _parse_host(self, line, current_object):
        current_object['ip_netmask'] = line.split()[-1]
        self.logger.debug(f'Parsed host: {current_object}')

    def _parse_range(self, line, current_object):
        parts = line.split()
        range_start = ip_address(parts[1])
        range_end = ip_address(parts[2])
        current_object['ip_range'] = f'{range_start}-{range_end}'

    def _parse_fqdn(self, line, current_object):
        parts = line.split()
        current_object['fqdn'] = parts[-1]  # Ensure 'v4' or 'v6' is ignored
        self.logger.debug(f'Parsed fqdn: {current_object}')

    def _parse_network_object(self, line, current_object):
        parts = line.split()
        if parts[1] == 'object':
            obj_name = self.sanitize_name(parts[2])
            if 'members' not in current_object:
                current_object['members'] = []
            current_object['members'].append(obj_name)
            self.logger.debug(f'Added network-object member {obj_name} to {current_object["name"]}')
        elif parts[1] == 'host':
            self._parse_host_network_object(parts, current_object)
        else:
            self._parse_subnet_network_object(parts, current_object)

    def _parse_host_network_object(self, parts, current_object):
        ip_netmask = parts[2]
        name = self.sanitize_name(f'H-{ip_netmask}')
        if ip_netmask not in self.addresses:
            self.addresses.add(ip_netmask)
            self.data['Address'].append({'name': name, 'ip_netmask': ip_netmask})
            self.logger.debug(f'Added new address: {name} with ip-netmask: {ip_netmask}')
        if 'members' not in current_object:
            current_object['members'] = []
        current_object['members'].append(name)

    def _parse_subnet_network_object(self, parts, current_object):
        if len(parts) == 3:
            try:
                cidr = self.netmask_to_cidr(parts[2])
                ip_netmask = f'{parts[1]}/{cidr}'
                name = self.sanitize_name(f'N-{parts[1]}-{cidr}')
            except ValueError as e:
                self.logger.error(f'Error parsing network-object: {e}')
                return
        else:
            ip_netmask = parts[1]
            name = self.sanitize_name(f'H-{ip_netmask}')
        if ip_netmask not in self.addresses:
            self.addresses.add(ip_netmask)
            self.data['Address'].append({'name': name, 'ip_netmask': ip_netmask})
            self.logger.debug(f'Added new address: {name} with ip-netmask: {ip_netmask}')
        if 'members' not in current_object:
            current_object['members'] = []
        current_object['members'].append(name)

    def _parse_port_object(self, line, current_object):
        if current_object and current_object['type'] == 'service-group':
            parts = line.split()
            port = self._get_port_from_parts(parts)
            if 'protocol' in current_object:
                service_name = self.sanitize_name(f'{current_object["protocol"].upper()}-{port}')
                if service_name not in self.processed_services:
                    self.add_service(port, current_object['protocol'], service_name)
                if 'members' not in current_object:
                    current_object['members'] = []
                current_object['members'].append(service_name)
                self.service_name_mapping[current_object['name']] = service_name
            else:
                self.logger.error(f'Missing protocol in service-group: {current_object["name"]}')

    def _get_port_from_parts(self, parts):
        if parts[1] == 'range':
            return f'{parts[2]}-{parts[3]}'
        elif parts[1] == 'eq':
            return map_port(parts[2])
        else:
            return map_port(parts[-1])

    def _parse_group_object(self, line, current_object, current_type):
        obj_name = self.sanitize_name(line.split()[-1])
        mapped_name = self.service_name_mapping.get(obj_name, obj_name)
        if 'members' not in current_object:
            current_object['members'] = []
        current_object['members'].append(mapped_name)
        self.logger.debug(f'Added group-object member {mapped_name} to {current_object["name"]}')
        if current_type == 'AddressGroup':
            self.unresolved_groups.setdefault(current_object['name'], []).append(obj_name)

    def _parse_service_destination_eq(self, line, current_object):
        if current_object and current_object.get('type') == 'Service':
            parts = line.split()
            port = map_port(parts[-1])
            protocol = 'tcp' if 'tcp' in line else 'udp'
            current_object['protocol'] = {protocol: {'port': port}}
            self.logger.debug(f'Parsed service: {current_object}')

    def add_service(self, port, protocol, service_name):
        if service_name not in self.processed_services:
            new_service = {
                'name': service_name,
                'protocol': {protocol: {'port': port}}
            }
            self.data['Service'].append(new_service)
            self.processed_services.add(service_name)
            self.logger.debug(f'Added new service: {new_service}')

    def save_current_object(self, obj, obj_type, first_pass):
        if obj_type == 'address':
            if 'ip_netmask' in obj or 'ip_range' in obj or 'fqdn' in obj:
                obj['name'] = self.sanitize_name(obj['name'])
                self.data['Address'].append(obj)
        elif obj_type == 'AddressGroup':
            obj['name'] = self.sanitize_name(obj['name'])
            obj['static'] = obj.pop('members', [])
            if first_pass:
                self.logger.debug(f'Saved AddressGroup for first pass: {obj["name"]} with members: {obj["static"]}')
            else:
                self.logger.debug(f'Saved AddressGroup for subsequent pass: {obj["name"]} with members: {obj["static"]}')
            self.data['AddressGroup'].append(obj)
        elif obj_type == 'Service':
            protocol = list(obj['protocol'].keys())[0]
            port = obj['protocol'][protocol]['port']
            obj['name'] = self.sanitize_name(f'{protocol.upper()}-{port}')
            self.data['Service'].append(obj)
            self.service_name_mapping[obj['name']] = obj['name']
        elif obj_type == 'ServiceGroup':
            self._save_service_group(obj)

    def _save_address(self, obj):
        if 'ip_netmask' in obj or 'ip_range' in obj or 'fqdn' in obj:
            obj['name'] = self.sanitize_name(obj['name'])
            self.data['Address'].append(obj)

    def _save_address_group(self, obj, first_pass):
        obj['name'] = self.sanitize_name(obj['name'])
        obj['static'] = obj.pop('members', [])
        self.logger.debug(f'Saved AddressGroup for {"first" if first_pass else "subsequent"} pass: {obj["name"]} with members: {obj["static"]}')
        self.data['AddressGroup'].append(obj)

    def _save_service(self, obj):
        protocol = list(obj['protocol'].keys())[0]
        port = obj['protocol'][protocol]['port']
        obj['name'] = self.sanitize_name(f'{protocol.upper()}-{port}')
        self.data['Service'].append(obj)
        self.service_name_mapping[obj['name']] = obj['name']

    def _save_service_group(self, obj):
        if 'members' not in obj:
            obj['members'] = []
        if len(obj['members']) == 1:
            single_member = obj['members'][0]
            self.service_name_mapping[obj['name']] = single_member
        else:
            obj['members'] = list(set([self.get_correct_service_name(member) for member in obj['members']]))
            self.data['ServiceGroup'].append(obj)

    def get_correct_service_name(self, member):
        return self.service_name_mapping.get(member, member)

    def resolve_groups(self):
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

    def process_single_service_groups(self):
        for service in self.single_service_groups:
            port = service['protocol'].get(list(service['protocol'].keys())[0]).get('port')
            if port.isdigit() or map_port(port) != port:
                self.data['Service'].append(service)
            else:
                self.data['ServiceGroup'].append(service)

    def filter_unsupported_services(self):
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

    def netmask_to_cidr(self, netmask):
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def sanitize_name(self, name):
        # Replace disallowed characters with underscore
        name = re.sub(r'[:\s/\\(),;=\'"&!@#$%^*+?<>{}~`]', '_', name).strip('_')
        # Remove consecutive underscores
        name = re.sub(r'__+', '_', name)
        # Check if the name is 'any' and replace it with 'any-grp' for address groups
        if name == 'any':
            return 'any-grp'
        return name[:63]

    def create_service(self, protocol, port):
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

    def create_tag(self, name, color):
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

    def is_supported_service(self, service_name):
        if service_name in self.unsupported_services:
            return False
        if service_name in self.service_name_mapping:
            return True
        for service in self.data['Service']:
            if service['name'] == service_name:
                return True
        return False

    def is_supported_service_group(self, group_name):
        for group in self.data['ServiceGroup']:
            if group['name'] == group_name:
                return all(self.is_supported_service(member) for member in group['members'])
        return False

    def _security_pre_rules_entries(self):
        security_rules = {}
        config_type = self._detect_config_type()
        rule_name_count = {}

        def sanitize_rule_name(name):
            name = self.sanitize_name(name)
            if name in rule_name_count:
                rule_name_count[name] += 1
                return f'{name}-{rule_name_count[name]}'
            rule_name_count[name] = 0
            return name

        def initialize_rule():
            return {
                'name': '',
                'description': '',
                'tag': set(),
                'from': set(),
                'source': set(['any']),
                'negate_source': False,
                'source_user': ['any'],
                'source_hip': ['any'],
                'to': set(),
                'destination': set(['any']),
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

        current_rule_id = None
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
                        continue
                    if 'ACCESS POLICY:' in remark:
                        description = remark
                        if current_rule_id not in security_rules:
                            security_rules[current_rule_id] = initialize_rule()
                        security_rules[current_rule_id]['description'] = description
                    elif 'L7 RULE:' in remark or 'L4 RULE:' in remark:
                        rule_name = sanitize_rule_name(remark.split(': ')[-1])
                        if current_rule_id not in security_rules:
                            security_rules[current_rule_id] = initialize_rule()
                        security_rules[current_rule_id]['name'] = rule_name
                elif 'advanced' in parts and current_rule_id:
                    if current_rule_id not in security_rules:
                        security_rules[current_rule_id] = initialize_rule()
                    current_rule = security_rules[current_rule_id]
                    action = 'allow' if 'permit' in parts else 'deny'
                    current_rule['action'] = action

                    from_zone, to_zone, source, destination, protocol = None, None, None, None, None
                    i = 0
                    while i < len(parts):
                        part = parts[i]
                        if part == 'ifc':
                            if not from_zone:
                                from_zone = parts[i + 1]
                            elif not to_zone:
                                to_zone = parts[i + 1]
                            i += 2
                        elif part == 'object-group':
                            if protocol is None:
                                protocol = self.get_correct_service_name(parts[i + 1])
                                tag_name = f'REVIEW-{self.hostname}'
                                tag = self.create_tag(tag_name, 'Red')
                                current_rule['application'] = set(['icmp', 'ping'])
                                current_rule['service'].add('application-default')
                                current_rule['tag'].add(tag)
                                i += 2
                            elif not source:
                                source = self.get_correct_service_name(parts[i + 1])
                                i += 2
                            elif not destination:
                                destination = self.get_correct_service_name(parts[i + 1])
                                i += 2
                            else:
                                service_name = self.get_correct_service_name(parts[i + 1])
                                current_rule['service'].add(service_name)
                                i += 2
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
                        elif part == 'any':
                            if not source:
                                source = 'any'
                            elif not destination:
                                destination = 'any'
                            i += 1
                        else:
                            i += 1

                    if from_zone:
                        current_rule['from'].add(from_zone)
                    if to_zone:
                        current_rule['to'].add(to_zone)
                    if source:
                        current_rule['source'] = set([source])
                    if destination:
                        current_rule['destination'] = set([destination])
                    if not current_rule['service']:
                        current_rule['service'] = set(['any'])

        consolidated_rules = []
        for rule in security_rules.values():
            rule['from'] = list(rule['from']) if rule['from'] else ['any']
            rule['to'] = list(rule['to']) if rule['to'] else ['any']
            rule['source'] = list(rule['source']) if rule['source'] else ['any']
            rule['destination'] = list(rule['destination']) if rule['destination'] else ['any']
            rule['service'] = list(rule['service']) if rule['service'] else ['any']
            rule['application'] = list(rule['application']) if rule['application'] else ['any']
            rule['tag'] = list(rule['tag']) if rule['tag'] else []
            rule['destination'] = [dest for dest in rule['destination'] if not dest.startswith(('TCP-', 'UDP-', 'IP-'))]
            if not rule['destination']:
                rule['destination'] = ['any']
            consolidated_rules.append(rule)

        self.logger.debug(f'FOUND THESE SECURITY PRE RULES: {consolidated_rules}')
        return consolidated_rules

    def _detect_config_type(self):
        for line in self.lines:
            if line.startswith('NGFW Version'):
                return 'firepower'
            elif line.startswith('ASA Version'):
                return 'asa'
        return 'unknown'

    def get_parsed_data(self):
        parsed_data = self.data.copy()
        parsed_data['security_post_rules'] = []  # Add empty security_post_rules
        self.logger.debug(f'Service name mapping: {self.service_name_mapping}')
        return parsed_data
