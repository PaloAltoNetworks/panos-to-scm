# panos-to-scm
Migrate Panorama or Local PANOS config(FROM XML file) to Strata Cloud Manager

# Requirements
First, you need to install dependencies. You can do this using:<br />
"pip install ."<br />

The credentials needed to request an access token can be defined in a configuration located at "$HOME/.panapi/config.yml"<br />
This is hidden folder in your current home directory:<br />
Windows would be C:\users\<username>\.panapi\config.yml<br />
Macos /Users/<username>/.panapi/config.yml<br />
Linux /home/<username>/.panapi<br />
```yaml
---
client_id: policy-import@123456789.iam.panserviceaccount.com
client_secret: abc12345-52b6-405c-a754-c2fffffb3561
tsg_id: 123456789
```

## Update the following
Update xml_file_path from main() with your XML file export of Panorama or Local Firewall running config

## Currently Support Features:

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
