import xml.etree.ElementTree as ET
import logging
import re

class XMLParser:
    def __init__(self, file_path, config_type, device_group_name=None):
        self.file_path = file_path
        self.config_type = config_type
        self.device_group_name = device_group_name
        self.tree = ET.parse(self.file_path)
        self.root = self.tree.getroot()
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Initialized XMLParser with file_path: {self.file_path}, config_type: {self.config_type}, device_group_name: {self.device_group_name}")

    def _get_base_xpath(self, path_dict):
        if self.config_type == 'panorama/shared':
            return path_dict.get('shared')
        elif self.config_type == 'panorama/device-group':
            if self.device_group_name:
                try:
                    return path_dict.get('device-group', '').format(device_group_name=self.device_group_name)
                except KeyError:
                    self.logger.error(f"Device group name not found in path_dict: {path_dict}")
                    raise
            else:
                self.logger.error("Device group name is required for panorama/device-group but is None.")
                raise ValueError("Device group name is required for panorama/device-group but is None.")
        return path_dict.get('local')

    def _sanitize_name(self, name: str) -> str:
        """
        Sanitize the name to match the API requirements.
        """
        sanitized_name = re.sub(r'[^a-zA-Z0-9._-]', '-', name)
        return sanitized_name[:63]

    def parse_config_and_set_scope(self, xml_file_path):
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        device_group_xpath = root.find('.//devices/entry/device-group')
        device_group_name = None
        scope_type = None
        scope_value = None

        if device_group_xpath is not None:
            config_choice = input("Is this a Panorama 'shared' configuration or 'device-group' configuration? Enter 'shared' or 'device-group': ").strip().lower()
            if config_choice == 'device-group':
                device_group_name = input("Enter the device-group name: ").strip()
                scope_type = input("Do you want to use a folder or a snippet? Enter 'folder' or 'snippet': ").strip().lower()
                scope_value = input(f'Enter the {scope_type} name (Use "All" for "Global"): ').strip()
                config_type = 'panorama/device-group'
            else:
                scope_type = input("Do you want to use a folder or a snippet? Enter 'folder' or 'snippet': ").strip().lower()
                scope_value = input(f'Enter the {scope_type} name (Use "All" for "Global"): ').strip()
                config_type = 'panorama/shared'
        else:
            scope_type = input("Do you want to use a folder or a snippet? Enter 'folder' or 'snippet': ").strip().lower()
            scope_value = input(f'Enter the {scope_type} name (Use "All" for "Global"): ').strip()
            config_type = 'local'

        scope_param = f"&{scope_type}={scope_value}"

        self.logger.debug(f"Parsed config and set scope: {scope_type}={scope_value}, config_type={config_type}, device_group_name={device_group_name}")

        return scope_param, config_type, device_group_name

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
        return {
            'URLCategory': self._parse_entries(self._url_category_entries),
            'URLAccessProfile': self._parse_entries(self._url_profiles_entries),
            'VulnerabilityProtectionProfile': self._parse_entries(self._vulnerability_profiles_entries),
            'AntiSpywareProfile': self._parse_entries(self._spyware_profiles_entries),
            'WildFireAntivirusProfile': self._parse_entries(self._antivirus_profiles_entries),
            'FileBlockingProfile': self._parse_entries(self._fileblocking_profiles_entries),
            'ProfileGroup': self._parse_entries(self._profile_group_entries),
            'Tag': self._parse_entries(self._tag_entries),
            'Address': self._parse_entries(self._address_entries),
            'AddressGroup': self._parse_entries(self._address_group_entries),
            'Service': self._parse_entries(self._service_entries),
            'ServiceGroup': self._parse_entries(self._service_group_entries),
            'ExternalDynamicList': self._parse_entries(self._edl_entries),
            'ApplicationFilter': self._parse_entries(self._application_filter_entries),
            'ApplicationGroup': self._parse_entries(self._application_group_entries),
            'Schedule': self._parse_entries(self._schedule_entries),
            'app_override_pre_rules': self._parse_entries(self._app_override_pre_rules_entries),
            'app_override_post_rules': self._parse_entries(self._app_override_post_rules_entries),
            'security_pre_rules': self._parse_entries(self._security_pre_rules_entries),
            'security_post_rules': self._parse_entries(self._security_post_rules_entries),
            'nat_pre_rules': self._parse_entries(self._nat_pre_rules_entries),
            'nat_post_rules': self._parse_entries(self._nat_post_rules_entries),
            'Application': self._parse_entries(self._application_entries),
            'Zones': self._parse_entries(self._zones),
            'DecryptionProfile': self._parse_entries(self._decryption_profiles_entries),
            'decryption_pre_rules': self._parse_entries(self._decryption_pre_rules_entries),
            'decryption_post_rules': self._parse_entries(self._decryption_post_rules_entries),
            'DNSSecurityProfile': self._parse_entries(self._dns_security_profiles_entries),
            'HipObject': self._parse_entries(self._hip_objects_entries),
            'HipProfile': self._parse_entries(self._hip_profiles_entries),
        }

    def parse_specific_types(self, object_types):
        parsed_data = {}
        method_map = {
            'URLCategory': self._url_category_entries,
            'URLAccessProfile': self._url_profiles_entries,
            'VulnerabilityProtectionProfile': self._vulnerability_profiles_entries,
            'AntiSpywareProfile': self._spyware_profiles_entries,
            'WildFireAntivirusProfile': self._antivirus_profiles_entries,
            'FileBlockingProfile': self._fileblocking_profiles_entries,
            'ProfileGroup': self._profile_group_entries,
            'Tag': self._tag_entries,
            'Address': self._address_entries,
            'AddressGroup': self._address_group_entries,
            'Service': self._service_entries,
            'ServiceGroup': self._service_group_entries,
            'ExternalDynamicList': self._edl_entries,
            'ApplicationFilter': self._application_filter_entries,
            'ApplicationGroup': self._application_group_entries,
            'Schedule': self._schedule_entries,
            'app_override_pre_rules': self._app_override_pre_rules_entries,
            'app_override_post_rules': self._app_override_post_rules_entries,
            'security_pre_rules': self._security_pre_rules_entries,
            'security_post_rules': self._security_post_rules_entries,
            'nat_pre_rules': self._nat_pre_rules_entries,
            'nat_post_rules': self._nat_post_rules_entries,
            'Application': self._application_entries,
            'Zones': self._zones,
            'DecryptionProfile': self._decryption_profiles_entries,
            'decryption_pre_rules': self._decryption_pre_rules_entries,
            'decryption_post_rules': self._decryption_post_rules_entries,
            'DNSSecurityProfile': self._dns_security_profiles_entries,
            'HipObject': self._hip_objects_entries,
            'HipProfile': self._hip_profiles_entries,
        }

        for obj_type in object_types:
            if obj_type in method_map:
                parsed_data[obj_type] = method_map[obj_type]()
            else:
                self.logger.warning(f"Unknown object type requested: {obj_type}")

        return parsed_data

    def _parse_entries(self, parse_function):
        return parse_function()

    def _url_category_entries(self):
        # Example: You can refactor individual parse methods in a similar way
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
                'list': members if members else None
            }

            filtered_url_categories = {k: v for k, v in url_categorys.items() if v is not None}
            url_category.append(filtered_url_categories)

        return url_category

    def _url_profiles_entries(self):
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

            filtered_url_profiles = {k: v for k, v in url_profile.items() if v is not None}
            url_profiles.append(filtered_url_profiles)

        return url_profiles
    
    def _hip_objects_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/hip-objects/entry',
            'shared': './shared/profiles/hip-objects/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/hip-objects/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        hip_objects = []

        for entry in self.root.findall(base_xpath):
            hip_object = {
                'name': entry.get('name'),
            }
            
            description = entry.findtext('description')
            if description is not None:
                hip_object['description'] = description

            for category in ['host-info', 'anti-malware', 'patch-management', 'disk-backup', 'certificate', 'custom-checks', 'disk-encryption', 'firewall', 'data-loss-prevention']:
                category_elem = entry.find(category)
                if category_elem is not None:
                    parsed_category = self._parse_category(category_elem)
                    if parsed_category:  # Only add non-empty categories
                        hip_object[category.replace('-', '_')] = parsed_category

            # Remove any empty dictionaries
            hip_object = {k: v for k, v in hip_object.items() if v}

            hip_objects.append(hip_object)

        return hip_objects

    def _parse_category(self, category_elem):
        result = {}
        criteria = category_elem.find('criteria')
        if criteria is not None:
            result['criteria'] = self._parse_criteria(criteria, category_elem.tag)

        vendor = category_elem.find('vendor')
        if vendor is not None:
            result['vendor'] = self._parse_vendor(vendor)

        exclude_vendor = category_elem.find('exclude-vendor')
        if exclude_vendor is not None:
            try:
                result['exclude_vendor'] = self._toBool(exclude_vendor.text)
            except ValueError:
                # If the value is not 'yes' or 'no', we'll keep the original text
                result['exclude_vendor'] = exclude_vendor.text.lower()

        return result

    def _parse_criteria(self, criteria_elem, category):
        criteria = {}
        if category == 'host-info':
            for child in criteria_elem:
                if child.tag == 'os':
                    criteria['os'] = self._parse_os(child)
                elif child.tag in ['domain', 'client-version', 'host-id', 'host-name', 'serial-number']:
                    criteria[child.tag] = self._parse_comparison(child)
                elif child.tag == 'managed':
                    criteria['managed'] = child.text.lower() == 'yes'
        else:
            for child in criteria_elem:
                if child.tag in ['is-installed', 'managed', 'disk-encrypted', 'jailbroken', 'passcode-set']:
                    criteria[child.tag.replace('-', '_')] = child.text.lower() == 'yes'
                elif child.tag in ['is-enabled', 'real-time-protection']:
                    criteria[child.tag.replace('-', '_')] = child.text.lower()
                elif child.tag == 'virdef-version':
                    criteria['virdef_version'] = self._parse_comparison(child)
                elif child.tag == 'certificate-profile':
                    criteria['certificate_profile'] = child.text
                elif child.tag in ['product-version', 'last-scan-time', 'last-backup-time', 'client-version', 'domain', 'host-id', 'host-name', 'serial-number', 'imei', 'model', 'phone-number', 'tag']:
                    criteria[child.tag.replace('-', '_')] = self._parse_comparison(child)
                elif child.tag == 'os':
                    criteria['os'] = self._parse_os(child)
                elif child.tag == 'missing-patches':
                    missing_patches = {'check': child.findtext('check')}
                    patches = [patch.text for patch in child.findall('patches/member')]
                    if patches:
                        missing_patches['patches'] = patches
                    criteria['missing_patches'] = missing_patches
                elif child.tag == 'encrypted-locations':
                    criteria['encrypted_locations'] = [
                        {
                            'name': loc.findtext('name'),
                            'encryption_state': self._parse_comparison(loc.find('encryption-state'))
                        }
                        for loc in child.findall('entry')
                    ]
                # Add more specific parsing for other criteria as needed

        return criteria

    def _parse_comparison(self, elem):
        for comp in ['greater-equal', 'greater-than', 'is', 'is-not', 'less-equal', 'less-than', 'contains', 'within', 'not-within']:
            comp_elem = elem.find(comp)
            if comp_elem is not None:
                if comp == 'within' and elem.tag == 'virdef-version':
                    days = comp_elem.findtext('days')
                    if days is not None:
                        return {comp: {'days': int(days)}}
                return {comp.replace('-', '_'): comp_elem.text}
        return None

    def _parse_os(self, os_elem):
        contains = os_elem.find('contains')
        if contains is not None:
            for vendor in ['Microsoft', 'Apple', 'Google', 'Linux', 'Other']:
                vendor_elem = contains.find(vendor)
                if vendor_elem is not None:
                    return {'contains': {vendor: vendor_elem.text}}
        return None

    def _parse_vendor(self, vendor_elem):
        vendors = []
        for entry in vendor_elem.findall('entry'):
            vendor = {
                'name': entry.get('name'),
                'product': [prod.text for prod in entry.findall('product/member')]
            }
            vendors.append(vendor)
        return vendors

    def _hip_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/hip-profiles/entry',
            'shared': './shared/profiles/hip-profiles/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/hip-profiles/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        hip_profiles = []

        for entry in self.root.findall(base_xpath):
            hip_profile = {
                'name': entry.get('name')
            }

            # Parse description if present
            description = entry.findtext('description')
            if description is not None:
                hip_profile['description'] = description[:255]  # Limit to 255 characters as per API spec

            # Parse match
            match = entry.findtext('match')
            if match is not None:
                hip_profile['match'] = match[:2048]  # Limit to 2048 characters as per API spec

            # Validate name length
            if len(hip_profile['name']) > 31:
                self.logger.warning(f"HIP profile name '{hip_profile['name']}' exceeds 31 characters. It will be truncated.")
                hip_profile['name'] = hip_profile['name'][:31]

            # Validate name characters
            if not re.match(r'^[0-9a-zA-Z._-]+$', hip_profile['name']):
                self.logger.warning(f"HIP profile name '{hip_profile['name']}' contains invalid characters. It should only contain alphanumeric characters, dots, underscores, and hyphens.")

            hip_profiles.append(hip_profile)

        return hip_profiles

    def _vulnerability_profiles_entries(self):
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
                        action[action_type.tag.replace('-', '_')] = {}

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

                if action:
                    rule['action'] = action

                rules.append(rule)

            vulnerability_profile = {
                'name': profile_name,
                'rules': rules
            }

            if description:
                vulnerability_profile['description'] = description

            vulnerability_profiles.append(vulnerability_profile)

        return vulnerability_profiles

    def _spyware_profiles_entries(self):
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
                action = {}
                for action_type in rule_entry.find('action'):
                    if action_type.tag != 'default':
                        action[action_type.tag.replace('-', '_')] = {}

                rule = {
                    'name': rule_name,
                    'severity': severities,
                    'category': category.text if category is not None else 'any',
                    'packet_capture': packet_capture.text if packet_capture is not None else 'disable'
                }

                if threat_name and threat_name.lower() != 'any':
                    rule['threat_name'] = threat_name
                if action:
                    rule['action'] = action

                rules.append(rule)

            spyware_profile = {
                'name': profile_name,
                'rules': rules
            }
            if description:
                spyware_profile['description'] = description

            spyware_profiles.append(spyware_profile)

        return spyware_profiles

    def _dns_security_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/spyware/entry',
            'shared': './shared/profiles/spyware/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/spyware/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        dns_security_profiles = []

        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            botnet_domains_element = profile_entry.find('botnet-domains')
            if botnet_domains_element is not None:
                dns_security_profile = {
                    'name': profile_name,
                    'botnet_domains': {}
                }

                # Handle dns_security_categories
                dns_security_categories = []
                for category_entry in botnet_domains_element.findall('./dns-security-categories/entry'):
                    category = {
                        'name': category_entry.get('name'),
                        'log_level': category_entry.find('log-level').text if category_entry.find('log-level') is not None else 'default',
                        'action': category_entry.find('action').text if category_entry.find('action') is not None else 'default',
                        'packet_capture': category_entry.find('packet-capture').text if category_entry.find('packet-capture') is not None else 'disable'
                    }
                    dns_security_categories.append(category)

                # Handle lists
                lists = []
                for list_entry in botnet_domains_element.findall('./lists/entry'):
                    action_element = list_entry.find('./action/*')
                    action = {action_element.tag: {}} if action_element is not None else {}
                    list_item = {
                        'name': list_entry.get('name'),
                        'action': action,
                        'packet_capture': list_entry.find('packet-capture').text if list_entry.find('packet-capture') is not None else 'disable'
                    }
                    lists.append(list_item)

                # Handle sinkhole
                sinkhole_element = botnet_domains_element.find('sinkhole')
                sinkhole = {
                    'ipv4_address': 'pan-sinkhole-default-ip',
                    'ipv6_address': '::1'
                }
                if sinkhole_element is not None:
                    ipv4_element = sinkhole_element.find('ipv4-address')
                    ipv6_element = sinkhole_element.find('ipv6-address')
                    
                    if ipv4_element is not None:
                        ipv4_value = ipv4_element.text
                        # Ensure ipv4_address is within allowed values
                        if ipv4_value in ['127.0.0.1', 'pan-sinkhole-default-ip']:
                            sinkhole['ipv4_address'] = ipv4_value
                        else:
                            self.logger.warning(f"Invalid ipv4_address '{ipv4_value}' for profile '{profile_name}'. Using default 'pan-sinkhole-default-ip'.")
                    
                    if ipv6_element is not None:
                        ipv6_value = ipv6_element.text
                        # Ensure ipv6_address is the allowed value
                        if ipv6_value == '::1':
                            sinkhole['ipv6_address'] = ipv6_value
                        else:
                            self.logger.warning(f"Invalid ipv6_address '{ipv6_value}' for profile '{profile_name}'. Using default '::1'.")

                # Handle whitelist
                whitelist = []
                for whitelist_entry in botnet_domains_element.findall('./whitelist/entry'):
                    whitelist_item = {
                        'name': whitelist_entry.get('name'),
                        'description': whitelist_entry.find('description').text if whitelist_entry.find('description') is not None else ''
                    }
                    whitelist.append(whitelist_item)

                # Ensure there is at least one placeholder in the whitelist if it's empty
                if not whitelist:
                    whitelist.append({'name': 'placeholder', 'description': 'placeholder'})

                if dns_security_categories:
                    dns_security_profile['botnet_domains']['dns_security_categories'] = dns_security_categories
                dns_security_profile['botnet_domains']['lists'] = lists
                dns_security_profile['botnet_domains']['sinkhole'] = sinkhole
                dns_security_profile['botnet_domains']['whitelist'] = whitelist

                dns_security_profiles.append(dns_security_profile)

        return dns_security_profiles

    def _decryption_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/decryption/entry',
            'shared': './shared/profiles/decryption/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/decryption/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        decryption_profiles = []

        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')

            ssl_forward_proxy = {
                "auto_include_altname": False,
                "block_client_cert": False,
                "block_expired_certificate": False,
                "block_timeout_cert": False,
                "block_tls13_downgrade_no_resource": False,
                "block_unknown_cert": False,
                "block_unsupported_cipher": False,
                "block_unsupported_version": False,
                "block_untrusted_issuer": False,
                "restrict_cert_exts": False,
                "strip_alpn": False
            }
            
            ssl_inbound_proxy = {
                "block_if_hsm_unavailable": False,
                "block_if_no_resource": False,
                "block_unsupported_cipher": False,
                "block_unsupported_version": False
            }
            
            ssl_no_proxy = {
                "block_expired_certificate": False,
                "block_untrusted_issuer": False
            }
            
            ssl_protocol_settings = {
                "auth_algo_md5": False,
                "auth_algo_sha1": True,
                "auth_algo_sha256": True,
                "auth_algo_sha384": True,
                "enc_algo_3des": True,
                "enc_algo_aes_128_cbc": True,
                "enc_algo_aes_128_gcm": True,
                "enc_algo_aes_256_cbc": True,
                "enc_algo_aes_256_gcm": True,
                "enc_algo_chacha20_poly1305": True,
                "enc_algo_rc4": True,
                "keyxchg_algo_dhe": True,
                "keyxchg_algo_ecdhe": True,
                "keyxchg_algo_rsa": True,
                "max_version": "tls1-2",
                "min_version": "tls1-0"
            }

            # Parse ssl-forward-proxy
            ssl_forward_proxy_element = profile_entry.find('ssl-forward-proxy')
            if ssl_forward_proxy_element is not None:
                for key in ssl_forward_proxy.keys():
                    element = ssl_forward_proxy_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_forward_proxy[key] = element.text.lower() == 'yes'

            # Parse ssl-inbound-proxy
            ssl_inbound_proxy_element = profile_entry.find('ssl-inbound-proxy')
            if ssl_inbound_proxy_element is not None:
                for key in ssl_inbound_proxy.keys():
                    element = ssl_inbound_proxy_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_inbound_proxy[key] = element.text.lower() == 'yes'

            # Parse ssl-no-proxy
            ssl_no_proxy_element = profile_entry.find('ssl-no-proxy')
            if ssl_no_proxy_element is not None:
                for key in ssl_no_proxy.keys():
                    element = ssl_no_proxy_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_no_proxy[key] = element.text.lower() == 'yes'

            # Parse ssl-protocol-settings
            ssl_protocol_settings_element = profile_entry.find('ssl-protocol-settings')
            if ssl_protocol_settings_element is not None:
                for key in ssl_protocol_settings.keys():
                    element = ssl_protocol_settings_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_protocol_settings[key] = element.text.lower() == 'yes'
                
                max_version_element = ssl_protocol_settings_element.find('max-version')
                if max_version_element is not None:
                    ssl_protocol_settings['max_version'] = max_version_element.text
                
                min_version_element = ssl_protocol_settings_element.find('min-version')
                if min_version_element is not None:
                    ssl_protocol_settings['min_version'] = min_version_element.text

            decryption_profile = {
                "name": profile_name,
                "ssl_forward_proxy": ssl_forward_proxy,
                "ssl_inbound_proxy": ssl_inbound_proxy,
                "ssl_no_proxy": ssl_no_proxy,
                "ssl_protocol_settings": ssl_protocol_settings
            }

            decryption_profiles.append(decryption_profile)

        return decryption_profiles

    def _antivirus_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/virus/entry',
            'shared': './shared/profiles/virus/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/virus/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        antivirus_profiles = []
        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
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
                'rules': [
                    {
                        'analysis': 'public-cloud',
                        'application': ['any'],
                        'direction': "both",
                        'file_type': ['any'],
                        'name': 'all-files'
                    }
                ],
            }

            if description:
                antivirus_profile['description'] = description

            antivirus_profiles.append(antivirus_profile)

        return antivirus_profiles

    def _fileblocking_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/file-blocking/entry',
            'shared': './shared/profiles/file-blocking/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/file-blocking/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        fileblocking_profiles = []
        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None

            rules = []
            for rule_entry in profile_entry.findall('./rules/entry'):
                rule_name = rule_entry.get('name')
                application_elements = rule_entry.find('application')
                applications = [member.text for member in application_elements.findall('member')]
                file_type_elements = rule_entry.find('file-type')
                file_types = [member.text for member in file_type_elements.findall('member')]
                direction = rule_entry.find('direction').text
                action = rule_entry.find('action').text

                rule = {
                    'name': rule_name,
                    'application': applications,
                    'file_type': file_types,
                    'direction': direction,
                    'action': action
                }

                rules.append(rule)

            fileblocking_profile = {
                'name': profile_name,
                'rules': rules
            }
            if description:
                fileblocking_profile['description'] = description

            fileblocking_profiles.append(fileblocking_profile)

        return fileblocking_profiles

    def _profile_group_entries(self):
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
                profile_group['dns_security'] = spyware_members

            vulnerability_members = [member.text for member in entry.findall('./vulnerability/member')]
            if vulnerability_members:
                profile_group['vulnerability'] = vulnerability_members

            url_filtering_members = [member.text for member in entry.findall('./url-filtering/member')]
            if url_filtering_members:
                profile_group['url_filtering'] = url_filtering_members

            profile_groups.append(profile_group)

        return profile_groups

    @staticmethod
    def _map_color_code_to_color(color_code):
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

    def _tag_entries(self):
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
            tag_color = self._map_color_code_to_color(tag_color_element.text) if tag_color_element is not None else None

            tag = {'name': name}
            if tag_color:
                tag['color'] = tag_color

            tags.append(tag)

        return tags

    def _address_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/address/entry',
            'shared': './shared/address/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/address/entry'
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

            filtered_address = {k: v for k, v in address.items() if v is not None}
            addresses.append(filtered_address)

        return addresses

    def _address_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/address-group/entry',
            'shared': './shared/address-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/address-group/entry'
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

            filtered_address_group = {k: v for k, v in address_group.items() if v is not None}
            address_groups.append(filtered_address_group)

        return address_groups

    def _service_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/service/entry',
            'shared': './shared/service/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/service/entry'
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

            filtered_services = {k: v for k, v in service_data.items() if v is not None}
            service_entries.append(filtered_services)

        return service_entries

    def _service_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/service-group/entry',
            'shared': './shared/service-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/service-group/entry'
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

            filtered_service_groups = {k: v for k, v in service_group.items() if v is not None}
            service_groups.append(filtered_service_groups)

        return service_groups

    def _edl_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/external-list/entry',
            'shared': './shared/external-list/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/external-list/entry'
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
        if recurring_type == 'five-minute':
            recurring = {'five_minute': {}}
        else:
            recurring = {recurring_type: {}}
        url = element.find('url').text if element.find('url') is not None else 'N/A'
        profile = element.find('certificate-profile').text if element.find('certificate-profile') is not None else 'Default'

        return {
            'name': name,
            'type': {edl_type: {'recurring': recurring, 'url': url, 'certificate_profile': profile}},
        }

    def _application_filter_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application-filter/entry',
            'shared': './shared/application-filter/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/application-filter/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        application_filters = []
        for entry in self.root.findall(base_xpath):
            filter_entry = {"name": entry.get("name")}

            for category in ["category", "subcategory", "technology", "risk", "saas-certifications", "saas-risk"]:
                members = entry.find(f"./{category}")
                if members is not None:
                    filter_entry[category.replace('-', '_')] = [member.text for member in members.findall("./member")]

            tagging = entry.find("./tagging")
            if tagging is not None:
                no_tag = tagging.find("no-tag")
                if no_tag is not None:
                    filter_entry["tagging"] = {"no_tag": self._toBool(no_tag.text.strip())}

                tags = tagging.find("./tag/member")
                if tags is not None:
                    filter_entry["tagging"] = {"tag": [tag.text for tag in tagging.findall("./tag/member")]}
                else:
                    filter_entry["tagging"] = {"no_tag": True}

            for attribute in ["evasive", "excessive-bandwidth-use", "used-by-malware", "transfers-files", "has-known-vulnerabilities", "tunnels-other-apps", "prone-to-misuse", "pervasive", "is-saas", "new-appid"]:
                element = entry.find(attribute)
                if element is not None:
                    filter_entry[attribute.replace('-', '_')] = self._toBool(element.text.strip())

            application_filters.append(filter_entry)

        return application_filters

    def _application_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application-group/entry',
            'shared': './shared/application-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/application-group/entry'
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

    def _app_override_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/application-override/rules/entry',
            'shared': './shared/pre-rulebase/application-override/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/application-override/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        app_override_rules = []
        for entry in self.root.findall(base_xpath):
            application = entry.find('application')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = self._sanitize_name(entry.get('name'))
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            port = entry.find('port')
            protocol = entry.find('protocol')
            source = entry.findall('source/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')

            app_override_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'port': port.text,
                'protocol': protocol.text,
                'application': application.text,
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
            }
            filtered_app_override_rule = {k: v for k, v in app_override_rule.items() if v is not None}
            app_override_rules.append(filtered_app_override_rule)

        logging.debug(f'FOUND THESE APP PRE RULES: {app_override_rules}')
        return app_override_rules

    def _app_override_post_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/application-override/rules/entry',
            'shared': './shared/post-rulebase/application-override/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/application-override/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        if self.config_type == 'local' or not base_xpath:
            return []
        app_override_rules = []
        for entry in self.root.findall(base_xpath):
            application = entry.find('application')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = self._sanitize_name(entry.get('name'))
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            port = entry.find('port')
            protocol = entry.find('protocol')
            source = entry.findall('source/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')

            app_override_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'port': port.text,
                'protocol': protocol.text,
                'application': application.text,
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
            }
            filtered_app_override_rule = {k: v for k, v in app_override_rule.items() if v is not None}
            app_override_rules.append(filtered_app_override_rule)

        logging.debug(f'FOUND THESE APP POST RULES: {app_override_rules}')
        return app_override_rules

    def _security_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/security/rules/entry',
            'shared': './shared/pre-rulebase/security/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/security/rules/entry'
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
            schedule = entry.find('schedule')

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
                'action': action.text if action is not None else None,
                'profile_setting': {'group': [profile_setting.text]} if profile_setting is not None else None,
                'schedule': schedule.text if schedule is not None else None
            }
            if schedule is not None and schedule.text:
                logging.warning(f"Schedule detected, manually add {schedule.text} to rule '{name}'")

            filtered_security_rules = {k: v for k, v in security_rule.items() if v is not None}
            security_rules.append(filtered_security_rules)

        logging.debug(f'FOUND THESE SECURITY PRE RULES: {security_rules}')
        return security_rules

    def _security_post_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/security/rules/entry',
            'shared': './shared/post-rulebase/security/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/security/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        if self.config_type == 'local' or not base_xpath:
            return []
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
                'action': action.text if action is not None else None,
                'profile_setting': {'group': [profile_setting.text]} if profile_setting is not None else None,
                'schedule': schedule.text if schedule is not None else None
            }
            if schedule is not None and schedule.text:
                logging.warning(f"Schedule detected, manually add {schedule.text} to rule '{name}'")

            filtered_security_rules = {k: v for k, v in security_rule.items() if v is not None}
            security_rules.append(filtered_security_rules)

        logging.debug(f'FOUND THESE SECURITY POST RULES: {security_rules}')
        return security_rules

    def _decryption_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/decryption/rules/entry',
            'shared': './shared/pre-rulebase/decryption/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/decryption/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        decryption_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            type_element = entry.find('type')
            type_value = None
            if type_element is not None:
                type_children = list(type_element)
                if type_children:
                    type_key = type_children[0].tag
                    type_value = type_key.replace('-', '_')
            log_success = entry.find('log-success')
            log_fail = entry.find('log-fail')
            profile = entry.find('profile')
            profile_value = profile.text if profile is not None else 'best-practice'
            if profile_value == 'default':
                profile_value = 'best-practice'

            decryption_rule = {
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
                'service': [members.text for members in service] if service is not None else ['any'],
                'category': [members.text for members in category] if category is not None else ['any'],
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                'action': action.text if action is not None else None,
                'type': {type_value: {}} if type_value else None,
                'log_success': True if (log_success is not None and log_success.text == 'yes') else False,
                'log_fail': False if (log_fail is not None and log_fail.text == 'no') else True,
                'profile': profile_value
            }

            filtered_decryption_rules = {k: v for k, v in decryption_rule.items() if v is not None}
            decryption_rules.append(filtered_decryption_rules)

        logging.debug(f'FOUND THESE DECRYPT PRE RULES: {decryption_rules}')
        return decryption_rules

    def _decryption_post_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/decryption/rules/entry',
            'shared': './shared/post-rulebase/decryption/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/decryption/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        if self.config_type == 'local' or not base_xpath:
            return []
        decryption_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            type_element = entry.find('type')
            type_value = None
            if type_element is not None:
                type_children = list(type_element)
                if type_children:
                    type_key = type_children[0].tag
                    type_value = type_key.replace('-', '_')
            log_success = entry.find('log-success')
            log_fail = entry.find('log-fail')
            profile = entry.find('profile')
            profile_value = profile.text if profile is not None else 'best-practice'
            if profile_value == 'default':
                profile_value = 'best-practice'

            decryption_rule = {
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
                'service': [members.text for members in service] if service is not None else ['any'],
                'category': [members.text for members in category] if category is not None else ['any'],
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                'action': action.text if action is not None else None,
                'type': {type_value: {}} if type_value else None,
                'log_success': True if (log_success is not None and log_success.text == 'yes') else False,
                'log_fail': False if (log_fail is not None and log_fail.text == 'no') else True,
                'profile': profile_value
            }

            filtered_decryption_rules = {k: v for k, v in decryption_rule.items() if v is not None}
            decryption_rules.append(filtered_decryption_rules)

        logging.debug(f'FOUND THESE DECRYPT POST RULES: {decryption_rules}')
        return decryption_rules

    def _nat_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/nat/rules/entry',
            'shared': './shared/pre-rulebase/nat/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/nat/rules/entry'
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

            service_value = service.text if service is not None else 'any'

            # Handle destination translation
            destination_translation_dict = None
            if destination_translation is not None:
                translated_address = destination_translation.find('translated-address')
                translated_port = destination_translation.find('translated-port')
                destination_translation_dict = {}
                if translated_address is not None:
                    destination_translation_dict['translated_address'] = translated_address.text
                if translated_port is not None:
                    destination_translation_dict['translated_port'] = translated_port.text

            # Handle source translation
            source_translation_dict = None
            if source_translation is not None:
                dynamic_ip_and_port = source_translation.find('dynamic-ip-and-port')
                if dynamic_ip_and_port is not None:
                    translated_addresses = dynamic_ip_and_port.findall('translated-address/member')
                    source_translation_dict = {
                        'dynamic_ip_and_port': {
                            'translated_address': [addr.text for addr in translated_addresses] if translated_addresses else None
                        }
                    }

            nat_rule = {
                'name': name,
                'from': [member.text for member in from_zone] if from_zone else [],
                'to': [member.text for member in to_zone] if to_zone else [],
                'source': [member.text for member in source] if source else [],
                'destination': [member.text for member in destination] if destination else [],
                'service': service_value,
                'nat_type': nat_type.text if nat_type is not None else None,
                'description': description.text if description is not None else None,
                'disabled': disabled.text == 'yes' if disabled is not None else False,
                'tag': [member.text for member in tag] if tag else [],
                'source_translation': source_translation_dict,
                'destination_translation': destination_translation_dict,
                'active_active_device_binding': active_active_device_binding.text if active_active_device_binding is not None else None
            }

            filtered_nat_rule = {k: v for k, v in nat_rule.items() if v is not None}
            nat_rules.append(filtered_nat_rule)

        return nat_rules

    def _nat_post_rules_entries(self):
        base_xpath_dict = {
            'shared': './shared/post-rulebase/nat/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/nat/rules/entry'
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

            service_value = service.text if service is not None else 'any'

            # Handle destination translation
            destination_translation_dict = None
            if destination_translation is not None:
                translated_address = destination_translation.find('translated-address')
                translated_port = destination_translation.find('translated-port')
                destination_translation_dict = {}
                if translated_address is not None:
                    destination_translation_dict['translated_address'] = translated_address.text
                if translated_port is not None:
                    destination_translation_dict['translated_port'] = translated_port.text

            # Handle source translation
            source_translation_dict = None
            if source_translation is not None:
                dynamic_ip_and_port = source_translation.find('dynamic-ip-and-port')
                if dynamic_ip_and_port is not None:
                    translated_addresses = dynamic_ip_and_port.findall('translated-address/member')
                    source_translation_dict = {
                        'dynamic_ip_and_port': {
                            'translated_address': [addr.text for addr in translated_addresses] if translated_addresses else None
                        }
                    }

            nat_rule = {
                'name': name,
                'from': [member.text for member in from_zone] if from_zone else [],
                'to': [member.text for member in to_zone] if to_zone else [],
                'source': [member.text for member in source] if source else [],
                'destination': [member.text for member in destination] if destination else [],
                'service': service_value,
                'nat_type': nat_type.text if nat_type is not None else None,
                'description': description.text if description is not None else None,
                'disabled': disabled.text == 'yes' if disabled is not None else False,
                'tag': [member.text for member in tag] if tag else [],
                'source_translation': source_translation_dict,
                'destination_translation': destination_translation_dict,
                'active_active_device_binding': active_active_device_binding.text if active_active_device_binding is not None else None
            }

            filtered_nat_rule = {k: v for k, v in nat_rule.items() if v is not None}
            nat_rules.append(filtered_nat_rule)

        return nat_rules

    def _application_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application/entry',
            'shared': './shared/application/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/application/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        applications = []
        for entry in self.root.findall(base_xpath):
            application = self._convert_application(entry)
            applications.append(application)
        return applications

    def _schedule_entries(self):
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

    def _zones(self):
        tree = ET.parse(self.file_path)
        root = tree.getroot()

        zone_entries = []

        for zone_entry in root.findall('../devices/entry/vsys/entry/zone/entry'):
            zone_name = zone_entry.get('name')
            zone_protection_profile = zone_entry.find('.//zone-protection-profile')

            network_data = {}

            for layer in ['layer3', 'layer2', 'v-wire']:
                layer_element = zone_entry.find(f'.//{layer}')
                if layer_element is not None:
                    interfaces = [member.text for member in layer_element.findall('member')]
                    network_data[layer] = {'member': interfaces}

            entry_data = {
                '@name': zone_name,
                'network': network_data
            }

            if zone_protection_profile is not None:
                entry_data['network']['zone-protection-profile'] = zone_protection_profile.text

            zone_entries.append({'entry': entry_data})

        return zone_entries

    def _convert_application(self, application):
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
            obj['able_to_transfer_file'] = self._toBool(transferfiles.text.strip())

        noappidCaching = application.find("no-appid-caching")
        if noappidCaching is not None:
            obj['no_appid_caching'] = self._toBool(noappidCaching.text.strip())

        tunnapps = application.find("tunnel-applications")
        if tunnapps is not None:
            obj['tunnel_applications'] = self._toBool(tunnapps.text.strip())

        tunnelotherapps = application.find("tunnel-other-application")
        if tunnelotherapps is not None:
            obj['tunnel_other_application'] = self._toBool(tunnelotherapps.text.strip())

        pervasive = application.find("pervasive-use")
        if pervasive is not None:
            obj['pervasive_use'] = self._toBool(pervasive.text.strip())

        evasive = application.find("evasive-behavior")
        if evasive is not None:
            obj['evasive_behavior'] = self._toBool(evasive.text.strip())

        algdisable = application.find("alg-disable-capability")
        if algdisable is not None:
            obj['alg_disable_capability'] = algdisable.text.strip()

        consumebw = application.find("consume-big-bandwidth")
        if consumebw is not None:
            obj['consume_big_bandwidth'] = self._toBool(consumebw.text.strip())

        prone = application.find("prone-to-misuse")
        if prone is not None:
            obj['prone_to_misuse'] = self._toBool(prone.text.strip())

        malware = application.find("used-by-malware")
        if malware is not None:
            obj['used_by_malware'] = self._toBool(malware.text.strip())

        vulns = application.find("has-known-vulnerability")
        if vulns is not None:
            obj['has_known_vulnerability'] = self._toBool(vulns.text.strip())

        fileTypeIdent = application.find("file-type-ident")
        if fileTypeIdent is not None:
            obj['file_type_ident'] = self._toBool(fileTypeIdent.text.strip())

        virusIdent = application.find("virus-ident")
        if virusIdent is not None:
            obj['virus_ident'] = self._toBool(virusIdent.text.strip())

        dataIdent = application.find("data-ident")
        if dataIdent is not None:
            obj['data_ident'] = self._toBool(dataIdent.text.strip())

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

        if application.find("tag") is not None:
            tags = application.findall(".//tag/member")
            obj["tag"] = [tag.text for tag in tags]

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
                        objSignature['order_free'] = self._toBool(orderFree.text.strip())

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

                    signatures.append(objSignature)

            obj['signature'] = signatures

        return obj

    def _toBool(self, value):
        if value.lower() == 'yes':
            return True
        elif value.lower() == 'no':
            return False
        else:
            raise ValueError(f"Cannot convert {value} to boolean")