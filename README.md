# panos-to-scm
Migrate Panorama or Local PANOS config(FROM XML file) to Strata Cloud Manager


## Update the following
On main.py update client_id, tsg_id with your Service Account information.

Currently using environment variables to store your secret
--Set environment variable for your secret key from your API service account
--In MacOS/Linux "export CLIENT_SECRET=your-text-string" In Windows CMD "setx CLIENT_SECRET your-text-string"

Additionally, update xml_file_path with your XML file export of Panorama or Local Firewall running config

## Currently Support Features:

-External Dynamic List - IP and URL.. Missing Certificate Profile for now<br />
-Custom URL Categories<br />
-URL Filter Profiles<br />
-Vulnerability Profiles<br />
-Anti-Spyware Profiles - SCM<br />
-Anti-Virus Profiles - SCM combines Virus/WildFire together.. As of now, it's importing Anti-Virus (but decoder's do not show currently) - Work in progress<br />
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
