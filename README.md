# panos-to-scm
Migrate Panorama or Local PANOS config(FROM XML file) to Strata Cloud Manager

# Requirements
First, you need to install the python-dotenv package. You can do this using pip:<br />
pip install python-dotenv

## Update the following
update ".env" file with your client_id, client_secret and tsg_id

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
