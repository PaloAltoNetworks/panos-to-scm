import logging
import re
from ipaddress import ip_network, ip_address
from . import map_port  # Import map_port from the __init__.py file

class CiscoParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.logger = logging.getLogger(__name__)
        self.data = {
            "Address": [],
            "AddressGroup": [],
            "Service": [],
            "ServiceGroup": [],
            "Unsupported": []
        }
        self.addresses = set()  # To keep track of already known addresses
        self.services = set()   # To keep track of already known services
        self.single_service_groups = []  # To keep track of single-member service groups
        self.unsupported_services = {"icmp"}
        self.unresolved_groups = {}  # To track unresolved groups and their members

    def parse(self):
        try:
            with open(self.file_path, 'r') as file:
                lines = file.readlines()
                self.parse_lines_first_pass(lines)
                self.process_single_service_groups()
                self.filter_unsupported_services()
                self.resolve_groups()
        except Exception as e:
            self.logger.error(f"Error parsing Cisco file: {e}", exc_info=True)

    def parse_lines_first_pass(self, lines):
        current_object = None
        current_type = None

        for line in lines:
            line = line.strip()
            self.logger.debug(f"Processing line: {line}")

            if line.startswith('object network'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                current_object = {"name": line.split()[-1], "type": "network"}
                current_type = "address"
            elif line.startswith('object-group network'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                current_object = {"name": line.split()[-1], "type": "network-group", "members": []}
                current_type = "AddressGroup"
            elif line.startswith('object service'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                current_object = {"name": line.split()[2], "type": "Service"}
                current_type = "Service"
            elif line.startswith('object-group service'):
                if current_object:
                    self.save_current_object(current_object, current_type, first_pass=True)
                parts = line.split()
                current_object = {"name": parts[-2], "type": "service-group", "protocol": parts[-1], "members": []}
                current_type = "ServiceGroup"
            elif line.startswith('description'):
                if current_object:
                    current_object["description"] = line.split(' ', 1)[1]
            elif line.startswith('subnet'):
                if current_object:
                    parts = line.split()
                    try:
                        subnet = ip_network(f"{parts[1]}/{self.netmask_to_cidr(parts[2])}")
                        current_object["ip_netmask"] = str(subnet)
                    except ValueError as e:
                        self.logger.error(f"Error parsing subnet: {e}")
                        continue
            elif line.startswith('host'):
                if current_object:
                    current_object["ip_netmask"] = line.split()[-1]
                    self.logger.debug(f"Parsed host: {current_object}")
            elif line.startswith('range'):
                if current_object:
                    parts = line.split()
                    range_start = ip_address(parts[1])
                    range_end = ip_address(parts[2])
                    current_object["ip_range"] = f"{range_start}-{range_end}"
            elif line.startswith('fqdn'):
                if current_object:
                    parts = line.split()
                    current_object["fqdn"] = parts[-1]  # This line ensures that "v4" or "v6" is ignored
                    self.logger.debug(f"Parsed fqdn: {current_object}")
            elif line.startswith('network-object'):
                if current_object:
                    parts = line.split()
                    if parts[1] == 'object':
                        obj_name = self.sanitize_name(parts[2])
                        current_object["members"].append(obj_name)
                        self.logger.debug(f"Added network-object member {obj_name} to {current_object['name']}")
                    elif parts[1] == 'host':
                        ip_netmask = parts[2]
                        name = self.sanitize_name(f"H-{ip_netmask}")
                        if ip_netmask not in self.addresses:
                            self.addresses.add(ip_netmask)
                            self.data["Address"].append({"name": name, "ip_netmask": ip_netmask})
                            self.logger.debug(f"Added new address: {name} with ip-netmask: {ip_netmask}")
                        current_object["members"].append(name)
                    else:
                        if len(parts) == 3:
                            try:
                                cidr = self.netmask_to_cidr(parts[2])
                                ip_netmask = f"{parts[1]}/{cidr}"
                                name = self.sanitize_name(f"N-{parts[1]}-{cidr}")
                            except ValueError as e:
                                self.logger.error(f"Error parsing network-object: {e}")
                                continue
                        else:
                            ip_netmask = parts[1]
                            name = self.sanitize_name(f"H-{ip_netmask}")

                        if ip_netmask not in self.addresses:
                            self.addresses.add(ip_netmask)
                            self.data["Address"].append({"name": name, "ip_netmask": ip_netmask})
                            self.logger.debug(f"Added new address: {name} with ip-netmask: {ip_netmask}")
                        current_object["members"].append(name)
            elif line.startswith('port-object'):
                if current_object:
                    parts = line.split()
                    if parts[1] == 'range':
                        port = f"{parts[2]}-{parts[3]}"
                    else:
                        port = map_port(parts[-1])  # Use map_port from __init__.py
                    current_object["members"].append(port)
            elif line.startswith('group-object'):
                if current_object:
                    obj_name = self.sanitize_name(line.split()[-1])
                    current_object["members"].append(obj_name)
                    self.logger.debug(f"Added group-object member {obj_name} to {current_object['name']}")
                    if current_type == "AddressGroup":
                        self.unresolved_groups.setdefault(current_object["name"], []).append(obj_name)
            elif line.startswith('service tcp destination eq') or line.startswith('service udp destination eq'):
                if current_object and current_object.get("type") == "Service":
                    parts = line.split()
                    port = map_port(parts[-1])
                    protocol = "tcp" if "tcp" in line else "udp"
                    current_object["protocol"] = {protocol: {"port": port}}
                    self.logger.debug(f"Parsed service: {current_object}")

        if current_object:
            self.save_current_object(current_object, current_type, first_pass=True)

    def save_current_object(self, obj, obj_type, first_pass):
        if obj_type == "address":
            if 'ip_netmask' in obj:
                obj["name"] = self.sanitize_name(obj["name"])
                self.data["Address"].append(obj)
            elif 'ip_range' in obj:
                obj["name"] = self.sanitize_name(obj["name"])
                self.data["Address"].append(obj)
            elif 'fqdn' in obj:
                obj["name"] = self.sanitize_name(obj["name"])
                self.data["Address"].append(obj)
        elif obj_type == "AddressGroup":
            obj["name"] = self.sanitize_name(obj["name"])
            obj["static"] = obj.pop("members", [])
            if first_pass:
                self.logger.debug(f"Saved AddressGroup for first pass: {obj['name']} with members: {obj['static']}")
            else:
                self.logger.debug(f"Saved AddressGroup for subsequent pass: {obj['name']} with members: {obj['static']}")
            self.data["AddressGroup"].append(obj)
        elif obj_type == "Service":
            protocol = list(obj["protocol"].keys())[0]
            port = obj["protocol"][protocol]["port"]
            obj["name"] = self.sanitize_name(f"{protocol.upper()}-{port}")
            self.data["Service"].append(obj)
        elif obj_type == "ServiceGroup":
            if len(obj["members"]) == 1:
                single_member = obj["members"][0]
                # Check if the single member already exists as a service or a service group
                if any(service["name"] == single_member for service in self.data["Service"]) or \
                any(group["name"] == single_member for group in self.data["ServiceGroup"]):
                    obj["name"] = self.sanitize_name(obj["name"])
                    obj["members"] = obj.pop("members", [])
                    obj.pop("protocol", None)  # Remove the protocol key if it exists
                    if "description" in obj:
                        obj.pop("description", None)  # Remove the description key if it exists
                    self.data["ServiceGroup"].append(obj)
                else:
                    new_service = {
                        "name": self.sanitize_name(obj["name"]),
                        "protocol": {obj["protocol"]: {"port": single_member}}
                    }
                    if "description" in obj:
                        new_service["description"] = obj["description"]
                    self.single_service_groups.append(new_service)
            else:
                obj["name"] = self.sanitize_name(obj["name"])
                obj["members"] = obj.pop("members", [])
                obj.pop("protocol", None)  # Remove the protocol key if it exists
                if "description" in obj:
                    obj.pop("description", None)  # Remove the description key if it exists
                self.data["ServiceGroup"].append(obj)

    def resolve_groups(self):
        passes = 0
        while self.unresolved_groups and passes < 10:
            self.logger.debug(f"Resolving groups, pass {passes + 1}")
            resolved_in_pass = []
            for group, members in self.unresolved_groups.items():
                if all(member in self.addresses for member in members):
                    self.logger.debug(f"Resolving group {group} with members: {members}")
                    self.data["AddressGroup"].append({"name": group, "static": members})
                    resolved_in_pass.append(group)
                    for member in members:
                        self.addresses.add(member)

            for group in resolved_in_pass:
                self.unresolved_groups.pop(group)

            passes += 1

        if self.unresolved_groups:
            unresolved_list = list(self.unresolved_groups.keys())
            self.logger.debug(f"Unresolved groups after all passes: {unresolved_list}")
            for group in unresolved_list:
                self.logger.debug(f"Group '{group}' unresolved members: {self.unresolved_groups[group]}")

    def process_single_service_groups(self):
        for service in self.single_service_groups:
            port = service["protocol"].get(list(service["protocol"].keys())[0]).get("port")
            if port.isdigit() or map_port(port) != port:
                self.data["Service"].append(service)
            else:
                self.data["ServiceGroup"].append(service)

    def filter_unsupported_services(self):
        # Remove unsupported service groups and their references
        for service_group in self.data["ServiceGroup"]:
            if "members" in service_group:
                service_group["members"] = [member for member in service_group["members"] if member not in self.unsupported_services]
        self.data["ServiceGroup"] = [group for group in self.data["ServiceGroup"] if "members" in group and group["members"]]

    def netmask_to_cidr(self, netmask):
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def sanitize_name(self, name):
        # Replace / with -, : with ., and truncate to 63 characters
        name = name.replace('/', '-').replace(':', '.')
        # Check if the name is 'any' and replace it with 'any-grp' for address groups
        if name == 'any':
            return 'any-grp'
        return name[:63]

    def get_parsed_data(self):
        return self.data
