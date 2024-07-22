## panos-to-scm
- **Migrate Panorama Device Group OR Local PANOS Firewall config into Strata Cloud Manager** 

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

### Step 2: Install the Package
"pip install ."

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

### Step 4: Executing main.py
- If you run `main.py` as is, it'll ask if you want to fetch a new `running_config.xml` from your PANOS Endpoint
- If you want to use an offline XML file, then default XML file name must be in project directory and named `running_config.xml`
- Otherwise, it'll get the full running config from your PANOS device(controlled at $HOME/.panapi/config.yml)
- Script will Parse all XML and create dictionary of object types and security rules
- Script will GET all objects and rules from SCM and then compare your XML and post new entries.
- Also handles rule ordering if something gets out of order(order determined by XML) which occurs in parallel processing
- Script currently will update objects if value has changed - example, address-group1 has members A,B,C in SCM
- If PANOS config has A,B,C,D - it will update and PUT D into it..
- **Append/Merge/Replace** - if you're importing multiple firewalls, and objects are at the same folder, the latest XML object is the master object.. So be aware.

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

### Currently Supported Features:

- **External Dynamic List**: Supports IP, URL, Domain lists
- **Custom URL Categories**
- **URL Filter Profiles**
- **Vulnerability Profiles**
- **Anti-Spyware Profiles**
- **Wildfire/Anti-Virus Profiles**: Disabled - complete manually before running script
- **File Blocking Profiles**
- **Decryption Profiles**
- **Profile Groups**
- **Tags**
- **Address Objects**
- **Address Groups**
- **Service Objects**
- **Service Groups**
- **Applications**: 
- **Application Filters**
- **Application Groups**
- **Security Rules**
- **NAT Rules**
- **Application Override Rules**
- **Decryption Policy Rules**