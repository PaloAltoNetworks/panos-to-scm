# panos-to-scm
Migrate Panorama or Local PANOS config to Strata Cloud Manager


On main.py update client_id, tsg_id with your Service Account information.

Currently using environment variables to store your secret
--Set environment variable for your secret key from your API service account
--In MacOS/Linux "export CLIENT_SECRET=your-text-string" In Windows CMD "setx CLIENT_SECRET your-text-string"

Additionally, update xml_file_path with your XML file export of Panorama or Local Firewall running config
