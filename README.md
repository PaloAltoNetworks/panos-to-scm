## 📢 End of Life Announcement for PANOS-TO-SCM Script

**Effective Date:** August 31, 2024

The **PANOS-TO-SCM** script is being officially deprecated and will no longer be maintained or supported after August 31, 2024. Following this date, this repository will be archived and made available in a read-only state. No further updates, bug fixes, or security patches will be provided. 

### What This Means for Users

- **No Support or Updates:** After the EOL date, the script will not receive any further updates, including bug fixes, enhancements, or security patches.
- **Read-Only Access:** The repository will remain accessible for reference purposes, but users are strongly advised against deploying it in production environments. Without ongoing maintenance, potential security vulnerabilities could emerge over time.
- **Alternative Access for Palo Alto Networks Employees and Contractors:** A supported version of this tool will continue to be available internally for Palo Alto Networks employees and contractors. You can access it at [Palo Alto Networks Spring Portal](https://spring.paloaltonetworks.com/echickerin/scm_migrator).

Thank you for your understanding and cooperation.

## panos-to-scm
- **Migrate Panorama Device Group OR Local PANOS Firewall config into Strata Cloud Manager NGFW**
- **Migrate Cisco ASA/Firepower running config into Strata Cloud Manager - In progress**

## Understand the following items before running
- **This script is as is, at your own risk, review license**
- **SCM supports "security profile groups" and not individual "security profiles" - make sure your policy reflects that**
- **SCM API doesn't fully support Antivirus/Wildfire API. Manually create this as it's treated as one profile. Script will reference "AntiVirus" profile from PANOS for security profile groups**
- **SCM API for security policies do not support adding schedules, if you have policies with schedules, manually add them to the policy**

### Step 1: Clone the Repository

```bash
git clone https://github.com/PaloAltoNetworks/panos-to-scm.git
cd panos-to-scm
```

### Step 2: Create a VENV and Install the Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### Step 3: SCM and PANOS Credentials
- **Common Services IAM account**
  - **Generate Service Account** Directions -> https://docs.paloaltonetworks.com/common-services/identity-and-access-access-management/manage-identity-and-access/add-service-accounts
- **SCM Credentials**: The credentials needed to request an access token can be defined in a configuration located at "$HOME/.panapi/config.yml"
  - **How to get there**:
  - **Window**s: `C:\users\<username>\.panapi\config.yml`
  - **MacOS**: `/Users/<username>/.panapi/config.yml`
  - **Linux**: `/home/<username>/.panapi/config.yml`

- Additionally add your PANOS NGFW/Panorama URL(make sure it ends in `/api/`) , Password and API Key
    - If you don't have API key for PANOS, the script will fetch API key and update config file
    - Optionally, you can ommit username/password and only apply the API key

```yaml
---
client_id: enter-username
client_secret: xxxxxxxxxxxxxxxxxxxxxx
tsg_id: enter-unique-tsg-here
palo_alto_ngfw_url: https://x.x.x.x/api/
palo_alto_password: service_account_password
palo_alto_username: service_account_name
palo_api_token: xxxxxxxxxxxxxxxxxxxxxx
```

### Step 4: Executing main.py for PAN-OS
- If you run `main.py` as is, it'll ask if you want to fetch a new `running_config.xml` from your PANOS Endpoint
- If you want to use an offline XML file, then default XML file name must be in project directory and named `running_config.xml`
- Otherwise, it'll get the full running config from your PANOS device(controlled at $HOME/.panapi/config.yml)
- Script will Parse all XML and create dictionary of object types and security rules
- Script will GET all objects and rules from SCM and then compare your XML and post new entries.
  - There is some conflict resolution logic built in for same name objects that require user input.
  - Options are:
    - Merge - Useful for groups/lists
    - Replace - Replace the SCM value with XML Value
    - Append - Creates a new object with appended name `_new`. This is still work in progress, policies will still reference the original attribute
    - Ignore - Ignore the conflict and move on
- Also handles rule ordering if something gets out of order(order determined by XML) which occurs in parallel processing

### Command Line Options:
- Check the "HELP" feature using `python main.py -h`
- Run Specific Objects: `python main.py -o Tag,Address,AddressGroup`
  - You can run one, or multiple, comma seperated like above example
- Run Security Rules Only: `python main.py -s`
- Run App Override Rules Only: `python main.py -p`
- Run Decryption Rules Only: `python main.py -d`
- Run NAT Rules Only: `python main.py -n`
- Run All Objects, Security, App Override, Decryption and NAT Rules: `python main.py -a`
- Default Behavior: Running `python main.py` without any options will run all objects only(no policies).

### Currently Supported PAN-OS Migration Features:

- **External Dynamic List**
- **Custom URL Categories**
- **URL Filter Profiles**
- **Vulnerability Profiles**
- **Anti-Spyware Profiles**
- **DNS Security Profiles**
- **File Blocking Profiles**
- **Decryption Profiles**
- **Profile Groups**
- **Tags**
- **Address Objects**
- **Address Groups**
- **Service Objects**
- **Service Groups**
- **Applications**
- **Application Filters**
- **Application Groups**
- **HIP Objects**
- **HIP Profiles**
- **Security Rules**
- **NAT Rules**
- **Application Override Rules**
- **Decryption Policy Rules**

## Cisco ASA/Firepower migration to SCM for PANOS
- Currently ASA/Firepower we need the running-config. `more system:running-config` or from FTD/FMC export the config. Must be in familiar ASA format
- Your cisco config must be in the project directory and named `cisco_config.txt`
- If you run `main.py` as is, it'll ask if you want to use the `cisco` or `panos` parser, type `cisco`
- Optionally, you can target specific object types such as `python main.py -o Address,AddressGroup`
- The script creates address objects in the form of:
  - N-address-CIDR for networks/ips that aren't objects in cisco config
- The script creates service objects in the form of:
  - There is a `map_port` method that handles terms such as `ssh, rsh, syslog, etc` and maps to port
  - This then creates object in format `TCP-22`
  - Additionally, service group objects with single members are treated as a "service" object
  - If another group references a `single member service group` it knows to reference the correct object
- Script will GET all objects and rules from SCM and then compare your `cisco_config.txt` and post new entries.
  - There is some conflict resolution logic built in for same name objects that require user input.
  - Options are:
    - Merge - Useful for groups/lists
    - Replace - Replace the SCM value with XML Value
    - Append - Creates a new object with appended name `_new`. This is still work in progress, policies will still reference the original attribute
    - Ignore - Ignore the conflict and move on
- Security Rules:
  - Supports ASA and Firepower L3/L4 Policies that reference service objects
  - If unsupported app/service (like icmp) it should tag rule for review
  - Currently destination zone is 'any' - route table lookup not implemented to determine dst zone
  - NAT rules are not considered, you will need to update Security policies with Pre-NAT IP Object


### Currently Supported Cisco ASA/Firepower Migration Features:
- **Address Objects**
- **Address Groups**
- **Service Objects**
- **Service Groups**
- **Security Rules**