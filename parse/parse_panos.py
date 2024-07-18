#/project/parse/parse_panos.py
import xml.etree.ElementTree as ET
import logging

class XMLParser:
    def __init__(self, file_path, config_type, device_group_name=None):
        self.file_path = file_path
        self.config_type = config_type
        self.device_group_name = device_group_name
        self.tree = ET.parse(self.file_path)
        self.root = self.tree.getroot()

    def parse_config_and_set_scope(self, xml_file_path):
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        device_group_xpath = root.find('.//devices/entry/device-group')
        device_group_name = None

        if device_group_xpath is not None:
            # Panorama configuration
            config_choice = input("Is this a Panorama 'shared' configuration or 'device-group' configuration? Enter 'shared' or 'device-group': ").strip().lower()
            if config_choice == 'device-group':
                device_group_name = input("Enter the device-group name: ").strip()
                confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
                folder_scope = confirm_folder
                config_type = 'panorama/device-group'
            else:
                confirm_global = input("Do you want these objects/policies to end up in the Global Folder on SCM? yes/no: ").strip().lower()
                folder_scope = "All" if confirm_global == 'yes' else input('Enter folder name: ').strip()
                config_type = 'panorama/shared'
        else:
            # Local configuration
            confirm_folder = input('What folder do you want the objects/policies to end up in? \n Use All for "Global" -Example "US-East-DC1" This is Case Sensitive: ').strip()
            folder_scope = confirm_folder
            config_type = 'local'

        return folder_scope, config_type, device_group_name

    def etree_to_dict(self, element):
        if element is None:
            return None

        if len(element) == 0:
            return element.text

        result = {}
        for child in element:
            child_result = self.etree_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_result)
            else:
                result[child.tag] = child_result

        return result

    def parse_all(self):
        parsed_data = {
            'URLCategory': self.url_category_entries(),
            'URLAccessProfile': self.url_profiles_entries(),
            'VulnerabilityProtectionProfile': self.vulnerability_profiles_entries(),
            'AntiSpywareProfile': self.spyware_profiles_entries(),
            'WildFireAntivirusProfile': self.antivirus_profiles_entries(),
            'ProfileGroup': self.profile_group_entries(),
            'Tag': self.tag_entries(),
            'Address': self.address_entries(),
            'AddressGroup': self.address_group_entries(),
            'Service': self.service_entries(),
            'ServiceGroup': self.service_group_entries(),
            'ExternalDynamicList': self.edl_entries(),
            'ApplicationFilter': self.application_filter_entries(),
            'ApplicationGroup': self.application_group_entries(),
            'Schedule': self.schedule_entries(),
            'security_pre_rules': self.security_pre_rules_entries(),
            'security_post_rules': self.security_post_rules_entries(),
            'nat_pre_rules': self.nat_pre_rules_entries(),
            'nat_post_rules': self.nat_post_rules_entries(),
            'Application': self.application_entries(),
            'Zones': self.zones()
        }
        return parsed_data

    def _get_base_xpath(self, path_dict):
        """Helper method to get the base xpath based on the config_type and device_group_name"""
        if self.config_type == 'panorama/shared':
            return path_dict.get('shared')
        elif self.config_type == 'panorama/device-group':
            return path_dict.get('device-group', '').format(device_group_name=self.device_group_name)
        return path_dict.get('local')  # This will return None if 'local' key is not present

    def application_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application/entry',
            'shared': './shared/application/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/application/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        applications = []
        
        for entry in self.root.findall(base_xpath):
            application = self.convert_application(entry)
            applications.append(application)
        
        return applications

    def schedule_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/schedule/entry',
            'shared': './shared/schedule/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/schedule/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        schedules = []

        for entry in self.root.findall(base_xpath):
            schedule_entry = {
                'name': entry.get('name'),
                'schedule_type': {}
            }

            schedule_type = entry.find('schedule-type')
            if schedule_type is not None:
                if schedule_type.find('recurring') is not None:
                    recurring = {}
                    recurring_type = schedule_type.find('recurring')

                    if recurring_type.find('daily') is not None:
                        daily_schedule = {
                            'daily': [member.text for member in recurring_type.find('daily').findall('member')]
                        }
                        recurring.update(daily_schedule)

                    if recurring_type.find('weekly') is not None:
                        weekly_schedule = {}
                        for day in ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']:
                            day_schedule = recurring_type.find('weekly').find(day)
                            if day_schedule is not None:
                                weekly_schedule[day] = [member.text for member in day_schedule.findall('member')]
                        recurring.update({'weekly': weekly_schedule})

                    schedule_entry['schedule_type']['recurring'] = recurring

                elif schedule_type.find('non-recurring') is not None:
                    non_recurring_times = [member.text for member in schedule_type.find('non-recurring').findall('member')]
                    schedule_entry['schedule_type']['non_recurring'] = non_recurring_times

            schedules.append(schedule_entry)

        return schedules

    def zones(self):
        tree = ET.parse(self.file_path)
        root = tree.getroot()

        zone_entries = []

        for zone_entry in root.findall('../devices/entry/vsys/entry/zone/entry'):
            zone_name = zone_entry.get('name')
            zone_protection_profile = zone_entry.find('.//zone-protection-profile')

            network_data = {}

            # Iterate over each layer type (layer3, layer2, v-wire) and add interfaces
            for layer in ['layer3', 'layer2', 'v-wire']:
                layer_element = zone_entry.find(f'.//{layer}')
                if layer_element is not None:
                    interfaces = [member.text for member in layer_element.findall('member')]
                    network_data[layer] = {'member': interfaces}

            # Construct the entry data for the API
            entry_data = {
                '@name': zone_name,
                'network': network_data
            }

            # Add zone-protection-profile if it exists
            if zone_protection_profile is not None:
                entry_data['network']['zone-protection-profile'] = zone_protection_profile.text

            # Add the formatted entry to the list
            zone_entries.append({'entry': entry_data})

        return zone_entries

    def url_category_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/custom-url-category/entry',
            'shared': './shared/profiles/custom-url-category/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/custom-url-category/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        url_category = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            list_elements = entry.find('list')
            type_element = entry.find('type')

            members = [member.text for member in list_elements.findall('member')] if list_elements is not None else []
            
            url_categorys = {
                'name': name,
                'description': description.text if description is not None else None,
                'type': type_element.text if type_element is not None else None,
                'list': members if members else None  # Set to None if members list is empty
            }

            # Filter out None values
            filtered_url_categories = {k: v for k, v in url_categorys.items() if v is not None}
            url_category.append(filtered_url_categories)

        return url_category

    def url_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/url-filtering/entry',
            'shared': './shared/profiles/url-filtering/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/url-filtering/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        url_profiles = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            block_elements = entry.find('block')
            alert_elements = entry.find('alert')
            allow_elements = entry.find('allow')
            continue_elements = entry.find('continue')

            url_profile = {
                'name': name,
                'description': description.text if description is not None else None,
                'block': [member.text for member in block_elements.findall('member')] if block_elements is not None else None,
                'alert': [member.text for member in alert_elements.findall('member')] if alert_elements is not None else None,
                'allow': [member.text for member in allow_elements.findall('member')] if allow_elements is not None else None,
                'continue': [member.text for member in continue_elements.findall('member')] if continue_elements is not None else None,
            }

            # Filter out None values from the tag dictionary
            filtered_url_profiles = {k: v for k, v in url_profile.items() if v is not None}
            url_profiles.append(filtered_url_profiles)

        return url_profiles

    def vulnerability_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/vulnerability/entry',
            'shared': './shared/profiles/vulnerability/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/vulnerability/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)  
        
        vulnerability_profiles = []

        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None
            
            rules = []
            for rule_entry in profile_entry.findall('./rules/entry'):
                rule_name = rule_entry.get('name')
                severity_elements = rule_entry.find('severity')
                severities = [member.text for member in severity_elements.findall('member')] if severity_elements is not None else []
                cve_elements = rule_entry.find('cve')
                cves = [member.text for member in cve_elements.findall('member')] if cve_elements is not None else []
                category = rule_entry.find('category')
                packet_capture = rule_entry.find('packet-capture')
                host = rule_entry.find('host')
                threat_name = rule_entry.find('threat-name')
                vendor_id_elements = rule_entry.find('vendor-id')
                vendor_ids = [member.text for member in vendor_id_elements.findall('member')] if vendor_id_elements is not None else []
                action = {}
                for action_type in rule_entry.find('action'):
                    if action_type.tag != 'default':
                        action[action_type.tag.replace('-', '_')] = {}  # Replace - with _ and assign an empty dictionary for each action type

                rule = {
                    'name': rule_name,
                    'severity': severities,
                    'cve': cves,
                    'category': category.text,
                    'packet_capture': packet_capture.text if packet_capture is not None else 'disable',
                    'host': host.text if host is not None else 'any',
                    'threat_name': threat_name.text if threat_name is not None else 'any',
                    'vendor_id': vendor_ids
                }
                
                if action:  # Add action only if it's not empty
                    rule['action'] = action

                rules.append(rule)

            vulnerability_profile = {
                'name': profile_name,
                'rules': rules
            }

            # Add description only if it exists
            if description:
                vulnerability_profile['description'] = description

            vulnerability_profiles.append(vulnerability_profile)

        return vulnerability_profiles
    
    def spyware_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/spyware/entry',
            'shared': './shared/profiles/spyware/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/spyware/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        spyware_profiles = []

        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None

            rules = []
            for rule_entry in profile_entry.findall('./rules/entry'):
                rule_name = rule_entry.get('name')
                threat_name_element = rule_entry.find('threat-name')
                threat_name = threat_name_element.text if threat_name_element is not None else None
                severity_elements = rule_entry.find('severity')
                severities = [member.text for member in severity_elements.findall('member')] if severity_elements is not None else []
                category = rule_entry.find('category')
                packet_capture = rule_entry.find('packet-capture')

                ##Handling the action element. The API doesn't accept "Default" action, so we'll ignore that..
                action = {}
                for action_type in rule_entry.find('action'):
                    if action_type.tag != 'default':
                        action[action_type.tag.replace('-', '_')] = {}  # Replace - with _ and assign an empty dictionary for each action type

                rule = {
                    'name': rule_name,
                    'severity': severities,
                    'category': category.text if category is not None else 'any',
                    'packet_capture': packet_capture.text if packet_capture is not None else 'disable'
                }

                if threat_name and threat_name.lower() != 'any':
                    rule['threat_name'] = threat_name
                if action:  # Add action only if it's not empty
                    rule['action'] = action

                rules.append(rule)

            spyware_profile = {
                'name': profile_name,
                'rules': rules
            }
            if description:
                spyware_profile['description'] = description

            # Add other fields like 'cloud_inline_analysis', 'inline_exception_edl_url', etc., if needed
            # spyware_profile['cloud_inline_analysis'] = False
            # spyware_profile['inline_exception_edl_url'] = []
            # spyware_profile['inline_exception_ip_address'] = []

            # Add 'mica_engine_spyware_enabled' and 'threat_exception' fields if necessary
            # This part depends on whether these fields exist in your XML and their structure

            spyware_profiles.append(spyware_profile)

        return spyware_profiles
    
    def antivirus_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/virus/entry',
            'shared': './shared/profiles/virus/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/virus/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        antivirus_profiles = []

        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            # packet_capture = profile_entry.get('packet-capture').text.replace('enabled', 'True') if profile_entry.get('packet-capture') is not None else "False"
            packet_capture = profile_entry.find('packet-capture') is not None and profile_entry.find('packet-capture').text.lower() == 'enabled'
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None

            decoders = []
            for decoder_entry in profile_entry.findall('./decoder/entry'):
                decoder_name = decoder_entry.get('name')
                action = decoder_entry.find('action').text.replace('-', '_') if decoder_entry.find('action') is not None else None
                wildfire_action = decoder_entry.find('wildfire-action').text.replace('-', '_') if decoder_entry.find('wildfire-action') is not None else None
                mlav_action = decoder_entry.find('mlav-action').text.replace('-', '_') if decoder_entry.find('mlav-action') is not None else None

                decoder = {
                    'name': decoder_name,
                    'action': action,
                    'wildfire_action': wildfire_action,
                    'mlav_action': mlav_action
                }
                decoders.append(decoder)

            antivirus_profile = {
                'name': profile_name,
                'packet_capture': packet_capture,
                'rules' : [
                    {
                        'analysis': 'public-cloud',
                        'application': ['any'],
                        'direction' : "both",
                        'file_type' : ['any'],
                        'name' : 'all-files'
                    }
                ],
                # 'decoders': decoders  ## To be updated when API Allows decoder entries
            }

            if description:
                antivirus_profile['description'] = description

            # Add other fields like 'mlav-engine-filebased-enabled', if needed
            # This part depends on whether these fields exist in your XML and their structure

            antivirus_profiles.append(antivirus_profile)

        return antivirus_profiles
    
    def profile_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profile-group/entry',
            'shared': './shared/profile-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profile-group/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        profile_groups = []

        for entry in self.root.findall(base_xpath):
            profile_group_name = entry.get('name')

            profile_group = {'name': profile_group_name}

            virus_members = [member.text for member in entry.findall('./virus/member')]
            if virus_members:
                profile_group['virus_and_wildfire_analysis'] = virus_members

            spyware_members = [member.text for member in entry.findall('./spyware/member')]
            if spyware_members:
                profile_group['spyware'] = spyware_members

            vulnerability_members = [member.text for member in entry.findall('./vulnerability/member')]
            if vulnerability_members:
                profile_group['vulnerability'] = vulnerability_members

            url_filtering_members = [member.text for member in entry.findall('./url-filtering/member')]
            if url_filtering_members:
                profile_group['url_filtering'] = url_filtering_members

            # Add other fields like 'dns_security' and 'file_blocking' if needed

            profile_groups.append(profile_group)

        return profile_groups
    
    @staticmethod
    def map_color_code_to_color(color_code):
        colorCodes = {
            'color1': 'Red',
            'color2': 'Green',
            'color3': 'Blue',
            'color4': 'Yellow',
            'color5': 'Copper',
            'color6': 'Orange',
            'color7': 'Purple',
            'color8': 'Gray',
            'color9': 'Light Green',
            'color10': 'Cyan',
            'color11': 'Light Gray',
            'color12': 'Blue Gray',
            'color13': 'Lime',
            'color14': 'Black',
            'color15': 'Gold',
            'color16': 'Brown',
            'color17': 'Olive',
            'color19': 'Maroon',
            'color20': 'Red-Orange',
            'color21': 'Yellow-Orange',
            'color22': 'Forest Green',
            'color23': 'Turquoise Blue',
            'color24': 'Azure Blue',
            'color25': 'Cerulean Blue',
            'color26': 'Midnight Blue',
            'color27': 'Medium Blue',
            'color28': 'Cobalt Blue',
            'color29': 'Violet Blue',
            'color30': 'Blue Violet',
            'color31': 'Medium Violet',
            'color32': 'Medium Rose',
            'color33': 'Lavender',
            'color34': 'Orchid',
            'color35': 'Thistle',
            'color36': 'Peach',
            'color37': 'Salmon',
            'color38': 'Magenta',
            'color39': 'Red Violet',
            'color40': 'Mahogany',
            'color41': 'Burnt Sienna',
            'color42': 'Chestnut'
            }
        return colorCodes.get(color_code)
    
    def tag_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/tag/entry',
            'shared': './shared/tag/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/tag/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        tags = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            tag_color_element = entry.find('color')
            tag_color = XMLParser.map_color_code_to_color(tag_color_element.text) if tag_color_element is not None else None

            tag = {'name': name}
            if tag_color:
                tag['color'] = tag_color

            tags.append(tag)

        return tags
    
    def address_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/address/entry',
            'shared': './shared/address/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/address/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        addresses = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            ip_netmask = entry.find('ip-netmask')
            ip_range = entry.find('ip-range')
            fqdn = entry.find('fqdn')
            description = entry.find('description')
            tag = entry.find('tag')

            address = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
                'ip_netmask': ip_netmask.text if ip_netmask is not None else None,
                'ip_range': ip_range.text if ip_range is not None else None,
                'fqdn': fqdn.text if fqdn is not None else None
            }

            # Filter out None values from the address dictionary
            filtered_address = {k: v for k, v in address.items() if v is not None}
            addresses.append(filtered_address)

        return addresses
    
    def address_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/address-group/entry',
            'shared': './shared/address-group/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/address-group/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        address_groups = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            static = entry.find('static')
            dynamic = entry.find('dynamic/filter')
            tag = entry.find('tag')

            address_group = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
                'dynamic': {'filter': dynamic.text} if dynamic is not None else None,
                'static': [member.text for member in static.findall('member')] if static is not None else None
            }

            # Filter out None values
            filtered_address_group = {k: v for k, v in address_group.items() if v is not None}
            address_groups.append(filtered_address_group)

        return address_groups
    
    def service_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/service/entry',
            'shared': './shared/service/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/service/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        service_entries = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            tag = entry.find('tag')
            protocol = entry.find('.//protocol')

            service_data = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
            }

            if protocol is not None:
                for proto in protocol:
                    if proto.tag in ('tcp', 'udp'):
                        port = proto.find('port')
                        source_port = proto.find('source-port')
                        protocol_data = {
                            'port': port.text if port is not None else None,
                            'source_port': source_port.text if source_port is not None else None,
                        }
                        filtered_protocol_data = {k: v for k, v in protocol_data.items() if v is not None}
                        service_data.update({
                            'protocol': {
                                proto.tag: filtered_protocol_data
                            }
                        })

            # Filter out None values
            filtered_services = {k: v for k, v in service_data.items() if v is not None}
            service_entries.append(filtered_services)

        return service_entries
    
    def service_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/service-group/entry',
            'shared': './shared/service-group/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/service-group/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        service_groups = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            members = entry.find('members')
            tag = entry.find('tag')

            service_group = {
                'name': name,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
                'members': [member.text for member in members.findall('member')] if members is not None else []
            }

            # Filter out None values
            filtered_service_groups = {k: v for k, v in service_group.items() if v is not None}
            service_groups.append(filtered_service_groups)

        return service_groups

    def edl_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/external-list/entry',
            'shared': './shared/external-list/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/external-list/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        edl_entries = []

        for entry in self.root.findall(base_xpath):
            edl_entry = self._parse_edl_entry(entry)
            if edl_entry:
                edl_entries.append(edl_entry)

        return edl_entries

    def _parse_edl_entry(self, entry):
        edl_entry_name = entry.get('name')
        type_element = entry.find('type')
        for edl_type in ['url', 'ip', 'domain']:
            element = type_element.find(edl_type)
            if element is not None:
                return self._create_edl_entry_dict(edl_entry_name, edl_type, element)
        return None

    def _create_edl_entry_dict(self, name, edl_type, element):
        recurring_element = element.find('recurring')
        recurring_type = next((child.tag for child in recurring_element), None) if recurring_element is not None else 'unknown'
        # If the recurring type is 'five-minute', return {} as the default value for recurring
        if recurring_type == 'five-minute':
            recurring = {}
        else:
            recurring = {recurring_type: {}}
        url = element.find('url').text if element.find('url') is not None else 'N/A'
        profile = element.find('certificate-profile').text if element.find('certificate-profile') is not None else 'Default'

        return {
            'name': name,
            'type': {edl_type: {'recurring': recurring, 'url': url, 'certificate_profile': profile}},
        }

    def application_filter_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application-filter/entry',
            'shared': './shared/application-filter/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/application-filter/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        application_filters = []
        for entry in self.root.findall(base_xpath):
            filter_entry = {"name": entry.get("name")}

            # Extract categories, subcategories, technologies, and other attributes
            for category in ["category", "subcategory", "technology", "risk", "saas-certifications", "saas-risk"]:
                members = entry.find(f"./{category}")
                if members is not None:
                    filter_entry[category.replace('-', '_')] = [member.text for member in members.findall("./member")]

            # Handle tagging
            tagging = entry.find("./tagging")
            if tagging is not None:
                no_tag = tagging.find("no-tag")
                if no_tag is not None:
                    filter_entry["tagging"] = {"no_tag": self.toBool(no_tag.text.strip())}

                tags = tagging.find("./tag/member")
                if tags is not None:
                    filter_entry["tagging"] = {"tag": [tag.text for tag in tagging.findall("./tag/member")]}
                else:
                    filter_entry["tagging"] = {"no_tag": True}

            # Boolean attributes
            for attribute in ["evasive", "excessive-bandwidth-use", "used-by-malware", "transfers-files", "has-known-vulnerabilities", "tunnels-other-apps", "prone-to-misuse", "pervasive", "is-saas", "new-appid"]:
                element = entry.find(attribute)
                if element is not None:
                    filter_entry[attribute.replace('-', '_')] = self.toBool(element.text.strip())

            application_filters.append(filter_entry)

        return application_filters
    
    def application_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application-group/entry',
            'shared': './shared/application-group/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/application-group/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        application_groups = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            members_elements = entry.find('members')

            application_group = {
                'name': name,
                'members': [member.text for member in members_elements.findall('member')] if members_elements is not None else []
            }

            application_groups.append(application_group)

        return application_groups

    def security_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/security/rules/entry',
            'shared': './shared/pre-rulebase/security/rules/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/pre-rulebase/security/rules/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        security_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            application = entry.findall('application/member')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            log_setting = entry.find('log-setting')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            profile_setting = entry.find('profile-setting/group/member')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            schedule= entry.find('schedule')

            security_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'source_user': [members.text for members in source_user] if source_user else ['any'],
                'source_hip': [member.text for member in entry.findall('source-hip/member')] or ['any'],
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'destination_hip': [member.text for member in entry.findall('destination-hip/member')] or ['any'],
                'application': [members.text for members in application] if application is not None else 'any',
                'service': [members.text for members in service] if service is not None else 'any',            
                'category': [members.text for members in category] if category is not None else 'any',
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                # 'log_setting': log_setting.text if log_setting is not None else None,
                'action': action.text if action is not None else None,
                # 'profile_setting': {'group': ['AlertOnly']}
                'profile_setting': {'group': [profile_setting.text]} if profile_setting is not None else None,
                'schedule': schedule.text if schedule is not None else None
            }
            if schedule is not None and schedule.text:
                logging.warning(f"Schedule detected, manually add {schedule.text} to rule '{name}'")            

            # Filter out None values from the address dictionary
            filtered_security_rules = {k: v for k, v in security_rule.items() if v is not None}
            security_rules.append(filtered_security_rules)

        logging.debug(f'FOUND THESE PRE RULES: {security_rules}')
        return security_rules
    
    def security_post_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/security/rules/entry',
            'shared': './shared/post-rulebase/security/rules/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/post-rulebase/security/rules/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        # Return an empty list if the configuration is local or if no base_xpath is found
        if self.config_type == 'local' or not base_xpath:
            return []

        logging.debug(f'POST RULE is going to check in xpath {base_xpath}')
        security_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            application = entry.findall('application/member')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            log_setting = entry.find('log-setting')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            profile_setting = entry.find('profile-setting/group/member')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            schedule = entry.find('schedule')

            security_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'source_user': [members.text for members in source_user] if source_user is not None else 'any',
                'source_hip': [member.text for member in entry.findall('source-hip/member')] or ['any'],
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'destination_hip': [member.text for member in entry.findall('destination-hip/member')] or ['any'],
                'application': [members.text for members in application] if application is not None else 'any',
                'service': [members.text for members in service] if service is not None else 'any',            
                'category': [members.text for members in category] if category is not None else 'any',
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                # 'log_setting': log_setting.text if log_setting is not None else None,
                'action': action.text if action is not None else None,
                # 'profile_setting': {'group': ['AlertOnly']}
                'profile_setting': {'group': [profile_setting.text]} if profile_setting is not None else None,
                'schedule': schedule.text if schedule is not None else None
            }
            if schedule is not None and schedule.text:
                logging.warning(f"Schedule detected, manually add {schedule.text} to rule '{name}'")
                
            filtered_security_rules = {k: v for k, v in security_rule.items() if v is not None}
            security_rules.append(filtered_security_rules)

        logging.debug(f'FOUND THESE POST RULES: {security_rules}')
        return security_rules

    def nat_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/nat/rules/entry',
            'shared': './shared/pre-rulebase/nat/rules/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/pre-rulebase/nat/rules/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        nat_rules = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            from_zone = entry.findall('from/member')
            to_zone = entry.findall('to/member')
            source = entry.findall('source/member')
            destination = entry.findall('destination/member')
            service = entry.find('service')
            nat_type = entry.find('nat-type')
            description = entry.find('description')
            disabled = entry.find('disabled')
            tag = entry.findall('tag/member')
            source_translation = entry.find('source-translation')
            destination_translation = entry.find('destination-translation')
            active_active_device_binding = entry.find('active-active-device-binding')

            # Ensure service is correctly extracted
            service_value = service.text if service is not None else 'any'

            # Parsing destination_translation to match OpenAPI specification
            destination_translation_dict = None
            if destination_translation is not None:
                translated_address = destination_translation.find('translated-address')
                translated_port = destination_translation.find('translated-port')
                dns_rewrite = destination_translation.find('dns-rewrite')

                destination_translation_dict = {
                    'translated_address_single': translated_address.text if translated_address is not None else None,
                    'translated_port': int(translated_port.text) if translated_port is not None else None,
                    'dns_rewrite': {
                        'direction': dns_rewrite.find('direction').text if dns_rewrite is not None else None
                    } if dns_rewrite is not None else None
                }
                # Remove None values
                destination_translation_dict = {k: v for k, v in destination_translation_dict.items() if v is not None}

            # Parsing source_translation to match OpenAPI specification
            source_translation_dict = None
            if source_translation is not None:
                dynamic_ip_and_port = source_translation.find('dynamic-ip-and-port')
                static_ip = source_translation.find('static-ip')
                dynamic_ip = source_translation.find('dynamic-ip')

                if dynamic_ip_and_port is not None:
                    interface_address = dynamic_ip_and_port.find('interface-address')
                    translated_addresses = [addr.text.strip() for addr in dynamic_ip_and_port.findall('translated-address/member') if addr.text.strip()]

                    dynamic_ip_and_port_dict = {}

                    if interface_address is not None:
                        dynamic_ip_and_port_dict['interface_address'] = {
                            'interface': interface_address.find('interface').text if interface_address.find('interface') is not None else None,
                            'ip': interface_address.find('ip').text if interface_address.find('ip') is not None else None,
                        }
                        # Remove None values from interface_address
                        dynamic_ip_and_port_dict['interface_address'] = {k: v for k, v in dynamic_ip_and_port_dict['interface_address'].items() if v is not None}

                        # If interface_address is empty, remove it from dynamic_ip_and_port_dict
                        if not dynamic_ip_and_port_dict['interface_address']:
                            dynamic_ip_and_port_dict.pop('interface_address', None)

                    if translated_addresses:
                        dynamic_ip_and_port_dict['translated_address_array'] = translated_addresses

                    source_translation_dict = {
                        'dynamic_ip_and_port': dynamic_ip_and_port_dict
                    }

                elif static_ip is not None:
                    translated_address_single = static_ip.find('translated-address')
                    bi_directional = static_ip.find('bi-directional')

                    source_translation_dict = {
                        'static_ip': {
                            'translated_address_single': translated_address_single.text if translated_address_single is not None else None,
                            'bi_directional': bi_directional.text if bi_directional is not None else None,
                        }
                    }
                elif dynamic_ip is not None:
                    translated_addresses = [addr.text.strip() for addr in dynamic_ip.findall('translated-address/member') if addr.text.strip()]
                    fallback = dynamic_ip.find('fallback')

                    fallback_dict = None
                    if fallback is not None:
                        fallback_translated_addresses = [addr.text.strip() for addr in fallback.findall('translated-address/member') if addr.text.strip()]
                        fallback_interface_address = fallback.find('interface-address')

                        fallback_dict = {
                            'translated_address_array': fallback_translated_addresses if fallback_translated_addresses else [],
                            'interface_address': {
                                'interface': fallback_interface_address.find('interface').text if fallback_interface_address.find('interface') is not None else None,
                                'ip': fallback_interface_address.find('ip').text if fallback_interface_address.find('ip') is not None else None,
                            } if fallback_interface_address is not None else {},
                        }

                        # Remove None values from fallback interface_address
                        fallback_dict['interface_address'] = {k: v for k, v in fallback_dict['interface_address'].items() if v is not None}

                        # If interface_address is empty, remove it from fallback_dict
                        if not fallback_dict['interface_address']:
                            fallback_dict.pop('interface_address', None)

                    source_translation_dict = {
                        'dynamic_ip': {
                            'translated_address_array': translated_addresses if translated_addresses else [],
                            'fallback': fallback_dict,
                        }
                    }

                    # Remove the translated_address_array key if it's empty
                    if not source_translation_dict['dynamic_ip']['translated_address_array']:
                        source_translation_dict['dynamic_ip'].pop('translated_address_array', None)

                # Remove None values from source_translation_dict
                if source_translation_dict:
                    source_translation_dict = {k: v for k, v in source_translation_dict.items() if v is not None}

            nat_rule = {
                'name': name,
                'from': [member.text for member in from_zone] if from_zone else [],
                'to': [member.text for member in to_zone] if to_zone else [],
                'source': [member.text for member in source] if source else [],
                'destination': [member.text for member in destination] if destination else [],
                'service': service_value,
                'nat_type': nat_type.text if nat_type else None,
                'description': description.text if description else None,
                'disabled': disabled.text == 'yes' if disabled else False,
                'tag': [member.text for member in tag] if tag else [],
                'source_translation': source_translation_dict,
                'destination_translation': destination_translation_dict,
                'active_active_device_binding': active_active_device_binding.text if active_active_device_binding else None
            }

            # Filter out None values from nat_rule
            filtered_nat_rules = {k: v for k, v in nat_rule.items() if v is not None}
            nat_rules.append(filtered_nat_rules)

        return nat_rules

    def nat_post_rules_entries(self):
        base_xpath_dict = {
            'shared': './shared/post-rulebase/nat/rules/entry',
            'device-group': f'./devices/entry/device-group/entry[@name="{self.device_group_name}"]/post-rulebase/nat/rules/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)

        if self.config_type == 'local' or not base_xpath:
            return []

        nat_rules = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            from_zone = entry.findall('from/member')
            to_zone = entry.findall('to/member')
            source = entry.findall('source/member')
            destination = entry.findall('destination/member')
            service = entry.find('service')
            nat_type = entry.find('nat-type')
            description = entry.find('description')
            disabled = entry.find('disabled')
            tag = entry.findall('tag/member')
            source_translation = entry.find('source-translation')
            destination_translation = entry.find('destination-translation')
            active_active_device_binding = entry.find('active-active-device-binding')

            # Ensure service is correctly extracted
            service_value = service.text if service is not None else 'any'

            # Parsing destination_translation to match OpenAPI specification
            destination_translation_dict = None
            if destination_translation is not None:
                translated_address = destination_translation.find('translated-address')
                translated_port = destination_translation.find('translated-port')
                dns_rewrite = destination_translation.find('dns-rewrite')

                destination_translation_dict = {
                    'translated_address_single': translated_address.text if translated_address is not None else None,
                    'translated_port': int(translated_port.text) if translated_port is not None else None,
                    'dns_rewrite': {
                        'direction': dns_rewrite.find('direction').text if dns_rewrite is not None else None
                    } if dns_rewrite is not None else None
                }
                # Remove None values
                destination_translation_dict = {k: v for k, v in destination_translation_dict.items() if v is not None}

            # Parsing source_translation to match OpenAPI specification
            source_translation_dict = None
            if source_translation is not None:
                dynamic_ip_and_port = source_translation.find('dynamic-ip-and-port')
                static_ip = source_translation.find('static-ip')
                dynamic_ip = source_translation.find('dynamic-ip')

                if dynamic_ip_and_port is not None:
                    interface_address = dynamic_ip_and_port.find('interface-address')
                    translated_addresses = [addr.text.strip() for addr in dynamic_ip_and_port.findall('translated-address/member') if addr.text.strip()]

                    dynamic_ip_and_port_dict = {}

                    if interface_address is not None:
                        dynamic_ip_and_port_dict['interface_address'] = {
                            'interface': interface_address.find('interface').text if interface_address.find('interface') is not None else None,
                            'ip': interface_address.find('ip').text if interface_address.find('ip') is not None else None,
                        }
                        # Remove None values from interface_address
                        dynamic_ip_and_port_dict['interface_address'] = {k: v for k, v in dynamic_ip_and_port_dict['interface_address'].items() if v is not None}

                        # If interface_address is empty, remove it from dynamic_ip_and_port_dict
                        if not dynamic_ip_and_port_dict['interface_address']:
                            dynamic_ip_and_port_dict.pop('interface_address', None)

                    if translated_addresses:
                        dynamic_ip_and_port_dict['translated_address_array'] = translated_addresses

                    source_translation_dict = {
                        'dynamic_ip_and_port': dynamic_ip_and_port_dict
                    }

                elif static_ip is not None:
                    translated_address_single = static_ip.find('translated-address')
                    bi_directional = static_ip.find('bi-directional')

                    source_translation_dict = {
                        'static_ip': {
                            'translated_address_single': translated_address_single.text if translated_address_single is not None else None,
                            'bi_directional': bi_directional.text if bi_directional is not None else None,
                        }
                    }
                elif dynamic_ip is not None:
                    translated_addresses = [addr.text.strip() for addr in dynamic_ip.findall('translated-address/member') if addr.text.strip()]
                    fallback = dynamic_ip.find('fallback')

                    fallback_dict = None
                    if fallback is not None:
                        fallback_translated_addresses = [addr.text.strip() for addr in fallback.findall('translated-address/member') if addr.text.strip()]
                        fallback_interface_address = fallback.find('interface-address')

                        fallback_dict = {
                            'translated_address_array': fallback_translated_addresses if fallback_translated_addresses else [],
                            'interface_address': {
                                'interface': fallback_interface_address.find('interface').text if fallback_interface_address.find('interface') is not None else None,
                                'ip': fallback_interface_address.find('ip').text if fallback_interface_address.find('ip') is not None else None,
                            } if fallback_interface_address is not None else {},
                        }

                        # Remove None values from fallback interface_address
                        fallback_dict['interface_address'] = {k: v for k, v in fallback_dict['interface_address'].items() if v is not None}

                        # If interface_address is empty, remove it from fallback_dict
                        if not fallback_dict['interface_address']:
                            fallback_dict.pop('interface_address', None)

                    source_translation_dict = {
                        'dynamic_ip': {
                            'translated_address_array': translated_addresses if translated_addresses else [],
                            'fallback': fallback_dict,
                        }
                    }

                    # Remove the translated_address_array key if it's empty
                    if not source_translation_dict['dynamic_ip']['translated_address_array']:
                        source_translation_dict['dynamic_ip'].pop('translated_address_array', None)

                # Remove None values from source_translation_dict
                if source_translation_dict:
                    source_translation_dict = {k: v for k, v in source_translation_dict.items() if v is not None}

            nat_rule = {
                'name': name,
                'from': [member.text for member in from_zone] if from_zone else [],
                'to': [member.text for member in to_zone] if to_zone else [],
                'source': [member.text for member in source] if source else [],
                'destination': [member.text for member in destination] if destination else [],
                'service': service_value,
                'nat_type': nat_type.text if nat_type else None,
                'description': description.text if description else None,
                'disabled': disabled.text == 'yes' if disabled else False,
                'tag': [member.text for member in tag] if tag else [],
                'source_translation': source_translation_dict,
                'destination_translation': destination_translation_dict,
                'active_active_device_binding': active_active_device_binding.text if active_active_device_binding else None
            }

            # Filter out None values from nat_rule
            filtered_nat_rules = {k: v for k, v in nat_rule.items() if v is not None}
            nat_rules.append(filtered_nat_rules)

        return nat_rules

    def convert_application(self, application):
        obj = {}
        obj['name'] = application.attrib['name']
        if application.find("description") is not None:
            obj['description'] = application.find("description").text.strip()

        subcategory = application.find("subcategory")
        if subcategory is not None:
            obj['subcategory'] = subcategory.text.strip()

        category = application.find("category")
        if category is not None:
            obj['category'] = category.text.strip()

        technology = application.find("technology")
        if technology is not None:
            obj['technology'] = technology.text.strip()

        parentapp = application.find("parent-app")
        if parentapp is not None:
            obj['parent_app'] = parentapp.text.strip()

        risk = application.find("risk")
        if risk is not None:
            obj['risk'] = int(risk.text.strip())

        transferfiles = application.find("able-to-transfer-file")
        if transferfiles is not None:
            obj['able_to_transfer_file'] = self.toBool(transferfiles.text.strip())

        noappidCaching = application.find("no-appid-caching")
        if noappidCaching is not None:
            obj['no_appid_caching'] = self.toBool(noappidCaching.text.strip())

        tunnapps = application.find("tunnel-applications")
        if tunnapps is not None:
            obj['tunnel_applications'] = self.toBool(tunnapps.text.strip())

        tunnelotherapps = application.find("tunnel-other-application")
        if tunnelotherapps is not None:
            obj['tunnel_other_application'] = self.toBool(tunnelotherapps.text.strip())

        pervasive = application.find("pervasive-use")
        if pervasive is not None:
            obj['pervasive_use'] = self.toBool(pervasive.text.strip())

        evasive = application.find("evasive-behavior")
        if evasive is not None:
            obj['evasive_behavior'] = self.toBool(evasive.text.strip())

        algdisable = application.find("alg-disable-capability")
        if algdisable is not None:
            obj['alg_disable_capability'] = algdisable.text.strip()

        consumebw = application.find("consume-big-bandwidth")
        if consumebw is not None:
            obj['consume_big_bandwidth'] = self.toBool(consumebw.text.strip())

        prone = application.find("prone-to-misuse")
        if prone is not None:
            obj['prone_to_misuse'] = self.toBool(prone.text.strip())

        malware = application.find("used-by-malware")
        if malware is not None:
            obj['used_by_malware'] = self.toBool(malware.text.strip())

        vulns = application.find("has-known-vulnerability")
        if vulns is not None:
            obj['has_known_vulnerability'] = self.toBool(vulns.text.strip())

        # Scan
        fileTypeIdent = application.find("file-type-ident")
        if fileTypeIdent is not None:
            obj['file_type_ident'] = self.toBool(fileTypeIdent.text.strip())

        virusIdent = application.find("virus-ident")
        if virusIdent is not None:
            obj['virus_ident'] = self.toBool(virusIdent.text.strip())

        dataIdent = application.find("data-ident")
        if dataIdent is not None:
            obj['data_ident'] = self.toBool(dataIdent.text.strip())

        # Timeouts
        timeout = application.find('timeout')
        if timeout is not None:
            obj['timeout'] = int(timeout.text.strip())

        udpTimeout = application.find('udp-timeout')
        if udpTimeout is not None:
            obj['udp_timeout'] = int(udpTimeout.text.strip())

        tcpTimeout = application.find('tcp-timeout')
        if tcpTimeout is not None:
            obj['tcp_timeout'] = int(tcpTimeout.text.strip())

        tcpTimeWaitTimeout = application.find('tcp-time-wait-timeout')
        if tcpTimeWaitTimeout is not None:
            obj['tcp_time_wait_timeout'] = int(tcpTimeWaitTimeout.text.strip())

        tcpHalfClosedTimeout = application.find('tcp-half-closed-timeout')
        if tcpHalfClosedTimeout is not None:
            obj['tcp_half_closed_timeout'] = int(tcpHalfClosedTimeout.text.strip())

        # default
        default = {}
        port = application.find('default/port')
        if port is not None:
            members = port.findall(".//member")
            if len(members) > 0:
                default['port'] = list(set(member.text for member in members))

        identByIpPort = application.find('default/ident-by-ip-protocol')
        if identByIpPort is not None:
            default['ident_by_ip_protocol'] = identByIpPort.text.strip()

        identByIcmpType = application.find('default/ident-by-icmp-type')
        if identByIcmpType is not None:
            code = identByIcmpType.find("code")
            if code is not None:
                default['ident_by_icmp_type'] = {'code': code.text.strip()}
            type = identByIcmpType.find("type")
            if type is not None:
                if default.get('ident_by_icmp_type') is None:
                    default['ident_by_icmp_type'] = {'type': type.text.strip()}
                else:
                    default['ident_by_icmp_type'].update({'type': type.text.strip()})

        identByIcmp6Type = application.find('default/ident-by-icmp6-type')
        if identByIcmp6Type is not None:
            code = identByIcmp6Type.find("code")
            if code is not None:
                default['ident_by_icmp6_type'] = {'code': code.text.strip()}
            type = identByIcmp6Type.find("type")
            if type is not None:
                if default.get('ident_by_icmp6_type') is None:
                    default['ident_by_icmp6_type'] = {'type': type.text.strip()}
                else:
                    default['ident_by_icmp6_type'].update({'type': type.text.strip()})

        if default != {}:
            obj['default'] = default

        # Tags
        if application.find("tag") is not None:
            tags = application.findall(".//tag/member")
            obj["tag"] = [tag.text for tag in tags]

        # signature
        signature = application.find("signature")
        signatures = []
        if signature is not None:
            sigs = signature.findall("./entry")
            if sigs is not None:
                for entry in sigs:
                    objSignature = {}
                    objSignature['name'] = entry.attrib['name']
                    comment = entry.find("comment")
                    if comment is not None:
                        objSignature['comment'] = comment.text.strip()
                    scope = entry.find("scope")
                    if scope is not None:
                        objSignature['scope'] = scope.text.strip()
                    orderFree = entry.find("order-free")
                    if orderFree is not None:
                        objSignature['order_free'] = self.toBool(orderFree.text.strip())

                    if entry.find("and-condition") is not None:
                        andConditions = entry.findall("and-condition/entry")
                        if andConditions is not None:
                            objAndConditions = []
                            for andCondition in andConditions:
                                objAndCondition = {}
                                objAndCondition['name'] = andCondition.attrib['name']
                                if andCondition.find('or-condition') is not None:
                                    orConditions = andCondition.findall("or-condition/entry")
                                    if orConditions is not None:
                                        objOrConditions = []
                                        for orCondition in orConditions:
                                            objOrCondition = {}
                                            objOrCondition['name'] = orCondition.attrib['name']
                                            objOrCondition['operator'] = {}
                                            # Pattern Matching
                                            patternMatch = orCondition.find("operator/pattern-match")
                                            if patternMatch is not None:
                                                objOrCondition['operator']['pattern_match'] = {}
                                                context = patternMatch.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['pattern_match']['context'] = context.text.strip()
                                                pattern = patternMatch.find("pattern")
                                                if pattern is not None:
                                                    objOrCondition['operator']['pattern_match']['pattern'] = pattern.text.strip()

                                                if patternMatch.find("qualifier") is not None:
                                                    qualifiers = patternMatch.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['pattern_match']['qualifier'] = objQualifiers

                                            # Greater Than
                                            greaterThan = orCondition.find("operator/greater-than")
                                            if greaterThan is not None:
                                                objOrCondition['operator']['greater_than'] = {}
                                                context = greaterThan.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['greater_than']['context'] = context.text.strip()
                                                value = greaterThan.find("value")
                                                if value is not None:
                                                    objOrCondition['operator']['greater_than']['value'] = int(value.text.strip())

                                                if greaterThan.find("qualifier") is not None:
                                                    qualifiers = greaterThan.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['greater_than']['qualifier'] = objQualifiers
                                            # Less than
                                            lessThan = orCondition.find("operator/less-than")
                                            if lessThan is not None:
                                                objOrCondition['operator']['less_than'] = {}
                                                context = lessThan.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['less_than']['context'] = context.text.strip()
                                                value = lessThan.find("value")
                                                if value is not None:
                                                    objOrCondition['operator']['less_than']['value'] = int(value.text.strip())

                                                if lessThan.find("qualifier") is not None:
                                                    qualifiers = lessThan.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['less_than']['qualifier'] = objQualifiers

                                            # Equal to
                                            equalTo = orCondition.find("operator/equal-to")
                                            if equalTo is not None:
                                                objOrCondition['operator']['equal_to'] = {}
                                                context = equalTo.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['equal_to']['context'] = context.text.strip()
                                                value = equalTo.find("value")
                                                if value is not None:
                                                    objOrCondition['operator']['equal_to']['value'] = int(value.text.strip())
                                                position = equalTo.find("position")
                                                if position is not None:
                                                    objOrCondition['operator']['equal_to']['position'] = position.text.strip()
                                                mask = equalTo.find("mask")
                                                if mask is not None:
                                                    objOrCondition['operator']['equal_to']['mask'] = mask.text.strip()

                                                if equalTo.find("qualifier") is not None:
                                                    qualifiers = equalTo.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['equal_to']['qualifier'] = objQualifiers

                                            objOrConditions.append(objOrCondition)
                                    objAndCondition["or_condition"] = objOrConditions
                                objAndConditions.append(objAndCondition)

                            objSignature['and_condition'] = objAndConditions
                    # Add Signature to the Array
                    signatures.append(objSignature)

            obj['signature'] = signatures

        return obj

    def toBool(self, value):
        if value.lower() == 'yes':
            return True
        elif value.lower() == 'no':
            return False
        else:
            raise ValueError(f"Cannot convert {value} to boolean")
