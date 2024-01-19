import scm.obj as obj

class AppConfig:
    def __init__(self):
        # Define the maximum number of workers for parallel processing
        self.max_workers = 3

        # Define the path to the XML file that contains the data to be processed
        self.xml_file_path = 'ISC-0517-1315.xml'  # Update as needed

        # Define the limit for how much objects to list..
        self.limit = '10000'

        # List of object types to be processed, as defined in your main.py
        self.obj_types = [
            obj.Tag, obj.Address, obj.AddressGroup, obj.Service, 
            obj.ServiceGroup, obj.ExternalDynamicList, obj.URLCategory, 
            obj.URLAccessProfile, obj.VulnerabilityProtectionProfile, 
            obj.AntiSpywareProfile, obj.WildFireAntivirusProfile, 
            obj.ProfileGroup, obj.ApplicationFilter, obj.ApplicationGroup
        ]

        # Add any other configuration settings that your script requires
        # For example:
        # self.some_other_setting = 'value'

    # Optionally, add methods to load or save configurations from/to files, databases, etc.
