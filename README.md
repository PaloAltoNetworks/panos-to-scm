## panos-to-scm
- **Pull Panorama Device Group OR Local PANOS Firewall config using their XMLAPI and migrate into Strata Cloud Manager** 

## Understand following items before running
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
- Script currently will update rules or objects if value has changed - example, address-group1 has members A,B,C in SCM
- If PANOS config has A,B,C,D - it will  update and PUT D into it..

### Command Line Options:
- Run Specific Objects: python main.py -o Tag,Address,AddressGroup
  - use main.py -h for list of all avilable object types. Put them in comma separated
- Run Security Rules Only: python main.py -s
- Run NAT Rules Only: python main.py -n
- Run All Objects, Security Rules, and NAT Rules: python main.py -a
- Default Behavior: Running python main.py without any options will run all objects only.

### Currently Supported Features:

- **External Dynamic List**: Supports IP, URL, Domain lists
- **Custom URL Categories**
- **URL Filter Profiles**
- **Vulnerability Profiles**
- **Anti-Spyware Profiles**
- **Wildfire/Anti-Virus Profiles**: This has been default disabled in /config/ as this feature isn't fully API supported
- **Profile Groups**
- **Tags**
- **Address Objects**
- **Address Groups**
- **Service Objects**
- **Service Groups**
- **Applications**: This is new feature, please check your import for verification. Thank you Albert Estevez Polo for the collaboration
- **Application Filters**
- **Application Groups**
- **Security Rules**
- **NAT Rules**: New feature, migration only supports initial commit. There is no ability to "move" rules currently
