## panos-to-scm
- **Purpose:** Pull Panorama Device Group OR Local PANOS Firewall config using their XMLAPI and migrate into Strata Cloud Manager.. 
    - Additionally, you can reference a static XML file and migrate into Strata Cloud Manager Folder

### Step 1: Clone the Repository

```bash
git clone https://github.com/PaloAltoNetworks/panos-to-scm.git
cd panos-to-scm
```

### Step 2: Install the Package
"pip install ."

### Step 3: SCM and PANOS Credentials

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

### Currently Supported Features:

- **External Dynamic List**: Supports IP, URL, Domain lists
- **Custom URL Categories**
- **URL Filter Profiles**
- **Vulnerability Profiles**
- **Anti-Spyware Profiles**
- **Anti-Virus Profiles**: SCM combines Virus/WildFire together.. As of now, it's importing Anti-Virus (but decoder's do not show currently)
- **Profile Groups**
- **Tags**
- **Address Objects**
- **Address Groups**
- **Service Objects**
- **Service Groups**
- **Application Filters**
- **Application Groups**
- **Security Rules**
- **NAT Rules**: API is not open yet, not tested.. Will test when API is open
