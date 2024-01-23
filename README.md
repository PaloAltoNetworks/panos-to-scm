# panos-to-scm
Migrate Panorama or Local PANOS config(FROM XML file) to Strata Cloud Manager

# Requirements
First, you need to install dependencies. You can do this using:<br />
"pip install ."<br />

The credentials needed to request an access token can be defined in a configuration located at "$HOME/.panapi/config.yml"<br />
This is a hidden folder in your current home directory:<br />
Windows: `C:\users\<username>\.panapi\config.yml`<br />
MacOS: `/Users/<username>/.panapi/config.yml`<br />
Linux: `/home/<username>/.panapi/config.yml`<br />

Additionally add your PANOS NGFW/Panorama URL, Password and API Key<br />
If you don't have API key for PANOS, the script will fetch API key and update config file<br />
Optionally, you can ommit username/password and only apply the API key<br />

```yaml
---
client_id: policy-import@123456789.iam.panserviceaccount.com
client_secret: abc12345-52b6-405c-a754-c2fffffb3561
tsg_id: 123456789
palo_alto_ngfw_url: https://10.255.255.4/api/
palo_alto_password: Password123456!@#
palo_alto_username: admin
palo_api_token: LUFRPT1tMlltKzFxamhTVnliTnN3Z1ZYS1JESk8yS2c9bUdERnl2bkk3ZzdVeGlGYkJRQXhZTmd1cE5GN2xTKzM3TTFlN3JlTmx1bDRmenhVMUtPWUE4WTZyVFJJNnV3Sg==
```

Update /config/__init__ with your configuration options<br />
Update xml_file_path with your XML file export of Panorama or Local Firewall running config<br />
Decide what obj_types you want to use<br />

## Main.py config
If you run main.py as is, it'll ask if you want to use static XML file (controlled at /config/__init__.py<br />
Otherwise, it'll get the full running config from your PANOS device(controlled at $HOME/.panapi/config.yml)<br />
Script will Parse all XML and create dictionary of object types and security rules<br />
Script will GET all objects and rules from SCM and then compare your XML and post new entries.<br />
Also handles rule ordering if something gets out of order(order determined by XML) which occurs in parallel processing<br />
Script currently will update rules or objects if value has changed - example, address-group1 has members A,B,C in SCM<br />
If PANOS config has A,B,C,D - it will  update and PUT D into it..<br />

## Currently Supported Features:

-External Dynamic List - IP and URL.. Missing Certificate Profile for now<br />
-Custom URL Categories<br />
-URL Filter Profiles<br />
-Vulnerability Profiles<br />
-Anti-Spyware Profiles - SCM<br />
-Anti-Virus Profiles - SCM combines Virus/WildFire together.. As of now, it's importing Anti-Virus (but decoder's do not show currently)<br />
-Profile Groups<br />
-Tags<br />
-Address Objects<br />
-Address Groups<br />
-Service Objects<br />
-Service Groups<br />
-Application Filters<br />
-Application Groups<br />
-Security Rules<br />
-NAT Rules - API is not open yet, not tested.. Will test when API is open<br />
