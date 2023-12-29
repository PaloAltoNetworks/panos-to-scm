# panos-to-scm
Migrate Panorama or Local PANOS config to Strata Cloud Manager


On main.py update client_id, tsg_id with your Service Account information.

Currently using environment variables to store your secret
--Set environment variable for your secret key from your API service account
--In MacOS/Linux "export CLIENT_SECRET=your-text-string" In Windows CMD "setx CLIENT_SECRET your-text-string"

Additionally, update xml_file_path with your XML file export of Panorama or Local Firewall running config

Currently Support Features:

-External Dynamic List - IP and URL.. Missing Certificate Profile for now
-Custom URL Categories
-URL Filter Profiles
-Vulnerability Profiles
-Anti-Spyware Profiles - SCM
-Anti-Virus Profiles - SCM combines Virus/WildFire together.. As of now, it's importing Anti-Virus (but decoder's do not show currently) - Work in progress
-Profile Groups
-Tags
-Address Objects
-Address Groups
-Service Objects
-Service Groups
-Application Filters
-Application Groups
-Security Rules
-NAT Rules - API is not open yet, not tested.. Will test when API is open
