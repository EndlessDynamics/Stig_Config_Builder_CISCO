#!/usr/bin/env python

"""
TITLE:           STIG_config_builder.py
VERSION:         1.4.2
LICENSE:         Apache-2.0 License
CREATOR:         Blake Becton
CONTACT:         https://github.com/EndlessDynamics/Stig_Config_Builder_CISCO
CREATED ON:      April 9, 2021
LAST UPDATED:    October 6, 2021
LIBRARY VERS:    Python v3.8.7, Jinja2

PURPOSE:        1) To instantly generate secure, STIG configurations that can be applied in
                a production environment to any Cisco device platform running IOS,
                IOS-XE, ASA, or Nexus code. The generated config ensures a minimum level
                of expected security configurations as per the decision of the technical
                lead(s) who manage the global/Corporate/or SMB network environment(s).

EXPECTATION:    1) Each generated config will be saved to a .txt file that gets
                automatically created. This file can be downloaded via SFTP in a terminal
                or via a GUI-based SFTP service such as SecureFX.
                2) At runtime, you will also have the oportunity to view the generated
                config in your existing vty terminal.

LIMITATIONS:    1) This 1.x version can only be used for Cisco network devices running
                the following Cisco code: IOS-Classic, IOS-XE, NX-OS, and ASA*.
                2) Version 2.1.0 will be first to fully support Cisco ASA platforms.
                NOTE: *denotes limited functionality.

REQUIREMENTS:   1) The below files and directories must exist RELATIVE to this script:
                - ./File_Mode/multidevice_instructions.txt
                - ./File_Mode/multidevice_example.csv
                - ./Generated_Configs/
                - ./STIG_Templates/aaa_servers.csv
                - ./STIG_Templates/aaa_servers_OOB.csv
                - ./STIG_Templates/aaa_servers_UNDERLAY.csv
                - ./STIG_Templates/aaa_servers_UNDERLAYv2.csv
                - ./STIG_Templates/ntp_servers.csv
                - ./STIG_Templates/ntp_servers_OOB.csv
                - ./STIG_Templates/ntp_servers_UNDERLAY.csv
                - ./STIG_Templates/ntp_servers_UNDERLAYv2.csv
                - ./STIG_Templates/site_passwords.csv
                - ./STIG_Templates/snmp_locations.csv
                - ./STIG_Templates/snmp_users_IOS.csv
                - ./STIG_Templates/snmp_users_ASA.csv
                - ./STIG_Templates/snmp_users_NEXUS.csv
                - ./Jinja_Templates/platform_IOS.j2
                - ./Jinja_Templates/platform_ASA.j2
                - ./Jinja_Templates/platform_NEXUS.j2

                2) User is prompted to answer 9 basic questions, such as:
                - What is the device name, management IP, device type, etc.

FUTURE CHANGES: 1) Starting with v2.1.0, full support for ASA platforms will be
                officially provided.
                3) At some future release, the 9 prompted questions requiring user input
                will be(can be) automatically extracted from various sources such as:
                - Nautobot database export
                - NetBox database export (v3.0 and greater)
                - Cisco Identity Services Engine database export (v2.4 and greater)
                - Infoblox NetMRI database export
                - a regularly maintained and updated YAML-based inventory file.
                This feature would provide an accurate, global inventory that can be
                obtained from multiple vendors IOT support corporate environments that
                deploy both paid-for and open-source DCIM/IT-Asset solutions.
                3) At some future release, I'll introduce Nautobot webhooks in an
                event-driven CI/CD pipeline to show how effective STIG security
                enforcement can be achieved with ZERO human interaction and ZERO
                man-hours costs.

CAVEATS:        1) At runtime, you will have the option to provide your own csv file 
                containing information for 2 or more devices that can generate all of
                the STIG configs simulataneously, placing them in individual files marked
                by hostname. (NOTE: The data in the csv file is required to be in a 
                special format.) It is potentially a huge advantage for those planning a
                future expansion, large quantity of device replacements(CERPS), or even a
                green-field by collecting device information ahead of time and storing it
                in a single csv file.
"""

import csv, sys, readline, os
from jinja2 import Environment, FileSystemLoader

# ========================================================================================
# List script variables.
# ========================================================================================

# >>>>>>>>> INTERNAL VARS <<<<<<<<<

# Main data container
input_results = []


# >>>>> EXTERNAL DEPENDENCIES <<<<<

# Jinja2 template engines
JINJA_TEMPLATE_IOS_IOSXE = "platform_IOS.j2"
JINJA_TEMPLATE_ASA = "platform_ASA.j2"
JINJA_TEMPLATE_NEXUS = "platform_NEXUS.j2"

# File prefix and Directory location for the resulting STIG config file
stig_config_file_PREFIX = "STIG_Config_"

# Relative path to important script files
stig_templates_path = "STIG_Templates/"         # To STIG template files containing Corporate data
file_mode_path = "File_Mode/"                   # To files used in 'File Mode'
stig_config_file_path = "./Generated_Configs/"  # To new STIG configuration files

# STIG Reference (SNMP): user and device location data
FILE_snmp_locations = stig_templates_path + "snmp_locations.csv"
FILE_snmp_users_IOS = stig_templates_path + "snmp_users_IOS.csv"
FILE_snmp_users_ASA = stig_templates_path + "snmp_users_ASA.csv"
FILE_snmp_users_NEXUS = stig_templates_path + "snmp_users_NEXUS.csv"
#FILE_snmp_users_NEXUS_7K = stig_templates_path + "snmp_users_NEXUS_7K.csv"      <---POTENTIAL FUTURE USE
#FILE_snmp_users_NEXUS_356K = stig_templates_path + "snmp_users_NEXUS_356K.csv"  <---POTENTIAL FUTURE USE

# STIG Reference (Passwords): site-specific password data
FILE_site_passwords = stig_templates_path + "site_passwords.csv"

# STIG Reference (AAA): AAA server data
FILE_aaa_servers = stig_templates_path + "aaa_servers.csv"
FILE_aaa_servers_UNDERLAY = stig_templates_path + "aaa_servers_UNDERLAY.csv"
FILE_aaa_servers_UNDERLAYv2 = stig_templates_path + "aaa_servers_UNDERLAYv2.csv"
FILE_aaa_servers_OOB = stig_templates_path + "aaa_servers_OOB.csv"

# STIG Reference (NTP): NTP server data
FILE_ntp_servers = stig_templates_path + "ntp_servers.csv"
FILE_ntp_servers_UNDERLAY = stig_templates_path + "ntp_servers_UNDERLAY.csv"
FILE_ntp_servers_UNDERLAYv2 = stig_templates_path + "ntp_servers_UNDERLAYv2.csv"
FILE_ntp_servers_OOB = stig_templates_path + "ntp_servers_OOB.csv"

"""
IMPORTANT_NOTE:

The below .txt file provides an Instructions/Reference Manual for importing data from
2 or more devices into the script for actioning.
If you alter this script, you MUST UPDATE the .txt file to reflect those changes in
order to ensure users can successfully use the 'File Mode' feature of this script!
"""
example_instructions = file_mode_path + "multidevice_instructions.txt"

"""
IMPORTANT_NOTE:
The below .csv file provides the user an Example File that can be ran at run-time to test
script outcomes using a file prior to importing large amounts of real device data.
If you alter the above .txt file, DO NOT forget to review and make any necessary
changes (if required) to the below example file that it references! This is critical in
assisting the script's users so they can test the 'File Mode' feature of this script
prior to importing mass device data.
"""
example_FILE = file_mode_path + "multidevice_example.csv"

# ========================================================================================
# Define script functions.
# ========================================================================================

def section_break(question_ID):
    print("\n\n\n")
    print(">"*10 + f" QUESTION {question_ID} of 9 " + "<"*10)

def prompt_networkType():
    '''
    NOTE: You can rename these options to better suite your network environment.
    The script has been written to support up to 6 different networks to allow for
    large, complex environments. You may rename the options however you must also rename
    them in the other parts of the script wherever they are found. Finally, you would
    need to rename any filters used in the Jinja2 templates located in the
    Jinja_Templates directory.
    '''
    print("\n     1  =  Network - UNDERLAY")    # Transport network
    print("     2  =  Network - UNDERLAYv2")    # An alternate transport network
    print("     3  =  Network - OVERLAY")       # Main data network
    print("     4  =  Network - DATACENTER_DC") # An alternate data network
    print("     5  =  Network - COMMERCIAL")    # An Edge network
    print("     6  =  Network - OOB\n")         # An out-of-band network

def prompt_deviceType():
    '''
    NOTE: The script has been written to support up to 7 different device types. The ASAs
    are divied up into 3 categories, mainly to allow for more intelligent automation if
    required in future version releases. If desired, you can rename these options to
    better reflect the device types in your network environment. If you rename them
    however, you must also rename them in all the other parts of this script, in order to
    prevent errors. Additionally, you would need to rename any filters that may or may
    not be used in the Jinja2 templates.
    '''
    print("\n     1  =  ASA - Physical Appliance [Not Functional ATT]")
    print("     2  =  ASA - hosted by Firepower 21xx Series Appliance [Not Functional ATT]")
    print("     3  =  ASA - hosted by Firepower 41xx Series Appliance [Not Functional ATT]")
    print("     4  =  Router - IOS-XR is not supported")      # IOS-XR support not planned because of SD-WAN
    print("     5  =  Switch - Nexus models")                 # Helps denote DataCenter switches
    print("     6  =  Switch - NON-Nexus")                    # Helps denote non-Nexus switches
    print("     7  =  OTHER - [RESERVED_FOR_FUTURE_USE]\n")   # Reserved for future development

def prompt_vdcType():
    '''
    NOTE: To ensure the correct SNMP 'User role' is parsed into the configuration, the
    vdc type for Nexus platforms must be identified.
    '''
    print("\n\n     1  =  Admin - The Administrative context for the Nexus switch")
    print("     2  =  Service - A non-Admin Virtual Device Context.\n")

def prompt_geoRegion():
    """
    NOTE: Many organizations optimize services based on relative location to a target
    server. This function was created for the purpose of providing dynamic
    assignments of certain config syntax when location-based dependencies exist.
    """
    print("\n     1  =  REGION_A")   # Example: West-US
    print("     2  =  REGION_B")     # Example: East-US
    print("     3  =  REGION_C")     # Example: Europe/Africa
    print("     4  =  REGION_D\n")   # Example: S.America

def prompt_snmpLocation():
    """
    NOTE: Any HQ will likely have a consolidated list of business locations that the
    organization manages. Include this data in the .csv file mentioned below, and enjoy
    the benefit of dynamic snmp location assignment in your device configs. Be sure to
    edit the final line in this function(Example: If device is...) to accurately denote
    which site is your Corporate HQ or, edit the statement to provide a helpful example.
    """
    print("\nSelecting the correct SNMP Location.\n")
    print("  Corporate Site ID")
    with open(FILE_snmp_locations) as snmpPrompt:
        csv_info = csv.reader(snmpPrompt)
        for row in csv_info:
            print(f"       {row[0]} - - - - - - {row[1]}")
    print("\nEnter the Corporate Site ID that cooresponds to your device's location. (View the available Site List above)")
    print("Example: If device is located at Corporate HQ (aka ID001), then enter:  ID001")

def prompt_siteContactPhone(siteID):
    """
    NOTE: If the SNMP contact information does not exist in the snmp_locations.csv
    file, the script will prompt the user to provide it. To skip this prompt or prevent
    it from occurring, update the .csv file with the necessary information.
    """
    print("\nThe SNMP Contact information for this site was not complete!")
    print("Contact info for the Network Department responsible for the management of this device must be provided before generating the config.")
    print(f"To continue, provide the Network Department's phone number for {siteID}.")

def prompt_sitePassword():
    """
    NOTE: This ensures the password used for all devices at a given site are
    configured correctly on all devices.. Ensure you update and maintain the
    corresponding .csv file referenced in this function.
    """
    print("\nSelecting the device's local credentials.\n")
    print("  Corporate Site ID")
    with open(FILE_site_passwords) as pwPrompt:
        csv_info = csv.reader(pwPrompt)
        for row in csv_info:
            print(f"       {row[0]}")
    print("\nEnter the Corporate Site ID that cooresponds to your device's location. (View the available Site List above)")
    print("Example: If device is located at Corporate HQ(aka ID001), then enter:  ID001")

def invalid_response_exit():
    print("\nYou entered an invalid response!\n EXITING SCRIPT...\n")
    sys.exit()

def contact_support(cisco_platform):
    """
    NOTE: Be sure to edit the below email address to reflect your organization's lead
    Network Department's email.
    """
    print(f"\nIf you need help generating configs for a(n) {cisco_platform} system, please contact:")
    print("Corporate HQ Network Department at: CorporateEmail@domain.com\n")

# =======================================================================================
# =======================================================================================
# Prompt for Interactive or File mode.
# =======================================================================================
# =======================================================================================

print("\n\n\n#####   CHOOSE YOUR MODE:   FILE OR INTERACTIVE   #####\n\n\n")
print("If you need to STIG many devices, this app allows you to generate multiple STIG configurations for 2 or more devices from a single csv file!")
print("   NOTE: The csv file MUST align with the required format, contain all req'd data, and provide that data for 2 or more devices.")
viewFormat_response = str(input("\n  Do you want to view instructions and see an example file before continuing? [y/n]:  "))
if viewFormat_response.lower() == "y":
    with open(example_instructions, 'r') as ex_instr:
        my_example = ex_instr.read()
        print(f"\n\n\n{my_example}")
    print("If you already uploaded a csv file via SFTP, you can benefit from the above with FILE MODE.")
    print("If you haven't, select INTERACTIVE MODE when prompted.")
    print("\n\n     1  =  INTERACTIVE MODE")
    print("     2  =  FILE MODE")
    print("\nHow do you want to proceed?")
    mode_prompt = str(input("   Enter 1 or 2:  "))
else:
    print("\n\n\nIf you already uploaded a csv file via SFTP, you can benefit from the above with FILE MODE.")
    print("If you haven't, select INTERACTIVE MODE when prompted.")
    print("\n\n     1  =  INTERACTIVE MODE")
    print("     2  =  FILE MODE")
    print("\nHow do you want to proceed?")
    mode_prompt = str(input("   Enter 1 or 2:  "))
if mode_prompt == "1":
    # ====================================================================================
    #
    #    `````*****<<<<<-----_____  Begin Interactive Mode  _____----->>>>>*****`````
    #
    # ====================================================================================

    # ====================================================================================
    # Identify the specific network type the device resides in.
    # ====================================================================================

    print("\n\n\n___INTERACTIVE MODE___\n\n")
    print(">"*10 + " QUESTION 1 of 9 " + "<"*10)
    prompt_networkType()
    print("Choose the network that matches the management plane network for this device.")
    networkType_response = str(input("   Enter your selection [1-6]:  "))
    if networkType_response == "1":
        networkType = "UNDERLAY"
    elif networkType_response == "2":
        networkType = "UNDERLAYv2"
    elif networkType_response == "3":
        networkType = "OVERLAY"
    elif networkType_response == "4":
        networkType = "DATACENTER_DC"
    elif networkType_response == "5":
        networkType = "COMMERCIAL"
    elif networkType_response == "6":
        networkType = "OOB"
    else:
        invalid_response_exit()

    # ====================================================================================
    # Identify the device's platform type.
    # ====================================================================================

    section_break(2)
    prompt_deviceType()
    print("Enter the number that corresponds to the device type.")
    deviceType_response = str(input("  Enter your selection [1-7]:   "))
    if deviceType_response == "1":
        deviceType = "ASA_Traditional"
    elif deviceType_response == "2":
        deviceType = "ASA_Firepower_21xx"
    elif deviceType_response == "3":
        deviceType = "ASA_Firepower_41xx"
    elif deviceType_response == "4":
        deviceType = "Router"
    elif deviceType_response == "5":
        deviceType = "Switch_Nexus"
    elif deviceType_response == "6":
        deviceType = "Switch_NON_NEXUS"
    elif deviceType_response == "7":     # Option 7 isn't broken. There's just no development for it yet.
        deviceType = "OTHER"
        print("\nThe STIG Config Builder does not support this option at this time.\nEXITING SCRIPT...\n")
        sys.exit()
    else:
        invalid_response_exit()

    # ====================================================================================
    # Obtain critical Switch details.
    # ====================================================================================
    '''
    NOTE: 
    '''
    if deviceType == "Switch_Nexus":
        print("\nSelect the correct VDC Type.")
        print("  If this config will be applied to an Admin context, select 'Admin'.")
        print("  Otherwise, select 'Service'.")
        prompt_vdcType()
        vdc_response = str(input("   Enter your selection [1 or 2]:  "))
        if vdc_response == "1":
            vdc_type = "admin"
        elif vdc_response == "2":
            vdc_type = "service"
        else:
            invalid_response_exit()
    else:
        vdc_type = "not_applicable"

    '''
    NOTE: I still need to test a wide-range of switch-stack configurations before
    allowing this type of situation to proceed through the script. If all tests pass, it
    is likely this section will be removed entirely.
    '''
    if deviceType == "Switch_NON_NEXUS":
        print("\nIs the switch participating in a switch stack?")
        stackResponse = str(input("   [y/n]:  "))
        stackCheck = stackResponse
    else:
        stackCheck = "n"
    if stackCheck.lower() == "y":
        print("\nThe STIG Config Builder does not support stacked switches at this time.\nEXITING SCRIPT...\n")
        sys.exit()
    elif stackCheck.lower() == "n":
        print("\nStackWise check - PASS\n")
    else:
        invalid_response_exit()

    # ====================================================================================
    # Identify the device hostname and derive the STIG config filename from it.
    # ====================================================================================
    '''
    NOTE: Although identifying the hostname is not quite necessary for devices currently in
    operations, it helps with 2 things:
    -Correcting any existing hostname typos,
    -Renaming a device if desired.
    '''
    section_break(3)
    print("\nProvide the device Hostname.\n")
    if deviceType == "ASA_Traditional":
        print("NOTE: If target device is a virtual context, ONLY enter the name of the virtual context.")
        print("   Good Example:   HQ-CE-FW1")
        print("   Good Example:   ADMIN-CE-FW1")
        print("    BAD Example:   CE-FW1/admin    <---Notice: system_name/default_context_name")
        contact_support("ASA")
        devName = str(input("  Enter the hostname:  "))
    elif deviceType == "ASA_Firepower_21xx" or deviceType == "ASA_Firepower_41xx":
        print("NOTE: If target device is a virtual context, ONLY enter the name of the virtual context.")
        print("   Good Example:   HQ-CE-FW1")
        print("   Good Example:   ADMIN-CE-FW1")
        print("    BAD Example:   CE-FW1/admin    <---Notice: system_name/default_context_name")
        contact_support("Firepower running ASA code")
        devName = str(input("  Enter the hostname:  "))
    elif deviceType == "Switch_Nexus":
        print("NOTE: If target device is a VDC, ONLY enter the name of the context.")
        print("   Good Example:   DC-SW1")
        print("   Good Example:   ADM-SW1")
        print("    BAD Example:   SW1/admin    <---Notice: system_name/default_context_name")
        contact_support("Nexus")
        devName = str(input("   Enter the hostname:  "))
    else:
        devName = str(input("   Enter the hostname:  "))

    # ====================================================================================
    # Define the STIG config filename and file path, based on the 'devName' variable.
    # ====================================================================================
    '''
    NOTE: For this application, obtaining a device's hostname in the section above is
    CRITICAL in that the file created by this script will use the hostname as part of the
    filename to distinguish it from other files. This prevents confusion when generating
    STIG configs for more than one device at a time, by naming all generated files with a
    unique, distinguishable filename that corresponds to each individual device.
    '''
    STIG_config_filename = stig_config_file_PREFIX + devName
    STIG_config_abs_path = stig_config_file_path + STIG_config_filename

    # ====================================================================================
    # Identify the management address.
    # ====================================================================================
    '''
    NOTE: Althought not used in the configuration ATT, this variable assists centralized
    HQ Network departments in updating/managing a Corporate TACACS/RADIUS server. This is
    evident in the message printed to the user's terminal during the final process of this
    application.
    '''
    section_break(4)
    print("\n   Good Example:   x.x.x.x")
    print("    Bad Example:   x.x.x.x/24")
    print("    Bad Example:   x.x.x.x x.x.x.x")
    print("\nProvide the device's Management IPv4 Address, without a subnet mask nor CIDR.")
    mgmt_ipaddr = str(input("  Enter the Management IP Address:  "))

    # ====================================================================================
    # Identify the management interface.
    # ====================================================================================
    '''
    NOTE: The 'Bad Examples' are provided to the user to prevent syntactical errors
    occurring in various older versions of IOS code.
    '''
    section_break(5)
    print("\nNote the lowercase chars and space between interface name and numerical identifier.")
    print("   Good Example:   vlan 10")
    print("   Good Example:   loopback 0")
    print("    Bad Example:   loopback0")
    print("    Bad Example:   vlan10")
    print("    Bad Example:   Vlan10")
    print("\nProvide the Interface Name configured with the Management IP Address.")
    mgmt_interf = str(input("   Enter the Interface Name:  "))

    # ====================================================================================
    # Identify if the management interface participates in VRF.
    # ====================================================================================
    '''
    NOTE: This is critical to ensure the device can reach all destination servers, which
    ensures network admins can remotely access the device after applying the STIG config.
    '''
    section_break(6)
    print("\nIs the Management Interface participating in VRF?")
    vrf_response = str(input("   [y/n]:  "))
    if vrf_response.lower() == "n":
        vrf_name = "no_vrf"
        vrf_exists = "no"
    elif vrf_response.lower() == "y":
        vrf_exists = "yes"
        print("\nEnter the exact name of the Management VRF [case-sensitive].")
        vrf_name = str(input("   VRF Name:  "))
    else:
        invalid_response_exit()
    
    # ====================================================================================
    # Optimize AAA and NTP Server selection based on Region.
    # ====================================================================================
    '''
    NOTE: This section helps optimize network design flow and latency for the management
    plane. This was originally brought up in the NOTE of the 'prompt_geoRegion()'
    function above. If your Corporate network environment does not contain admin servers
    (Cisco ACS/ISE, SYSLOG servers, NTP servers, etc) at multiple locations, simply
    provide the same IPs for all 'Regions' in the corresponding AAA and NTP .csv files
    mentioned below.
    '''
    section_break(7)
    print("\nOptimizing TACACS and NTP Server Selections...")
    prompt_geoRegion()
    print("Enter the number that corresponds to the device's regional location.")
    geoRegion_response = str(input("   Enter your selection:  "))
    if geoRegion_response == "1":
        geo_region = "REGION_A"
    elif geoRegion_response == "2":
        geo_region = "REGION_B"
    elif geoRegion_response == "3":
        geo_region = "REGION_C"
    elif geoRegion_response == "4":
        geo_region = "REGION_D"
    else:
        invalid_response_exit()
    ise_region = geo_region

    # AAA Server selection #
    '''
    NOTE: For your Transport Network, aka Underlay, typically there are fewer provided
    resources compared to the main Service Network, aka Overlay. This is evident in the
    number of AAA server IPs below that are servicing the Transport(UNDERLAY) and
    Alternate Transport(UNDERLAYv2) networks. 
    '''
    if networkType == "UNDERLAY":
        with open(FILE_aaa_servers_UNDERLAY) as aaaFile:
            csv_data = csv.reader(aaaFile)
            for row in csv_data:
                aaaServer_PRI = row[0]
                aaaServer_SEC = row[1]
    elif networkType == "UNDERLAYv2":
        with open(FILE_aaa_servers_UNDERLAYv2) as aaaFile:
            csv_data = csv.reader(aaaFile)
            for row in csv_data:
                aaaServer_PRI = row[0]
                aaaServer_SEC = row[1]
    elif networkType == "OOB":
        '''
        NOTE: You can enable/disable this section by choosing which subsection to comment
        out (Support OOB or Don't Support OOB). If you require OOB support, be sure the
        .csv file referenced below exists, and the variable the .csf file is assigned to
        at the top of this script is uncommented.
        Whatever your needs are, be sure to comment out the opposing subsection below.
        Finally, be sure your Jinja Template files can respond appropriately when OOB
        is selected as a networkType.
        '''
        # No OOB Support #
        #print(f"Determining AAA Servers for the {networkType} network is under development ATT.")
        #print("EXITING SCRIPT...")
        #sys.exit()
        #
        # OOB Support #
        with open(FILE_aaa_servers_OOB) as aaaFile:
            csv_data = csv.reader(aaaFile)
            if geo_region == "REGION_A":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            elif geo_region == "REGION_B":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            elif geo_region == "REGION_C":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            elif geo_region == "REGION_D":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            else:
                print("ERROR! Failed to identify the optimized AAA Server IPs.")
                print("To Troubleshoot: Review the script section named: AAA and NTP Server selection\n EXITING SCRIPT...\n")
                sys.exit()
    elif networkType != "UNDERLAY":
        '''
        NOTE: This final 'elif' statement performs a catch-all for any other
        'networkType' that is not residing in the Transport network. This helps minimize
        the management of data (by reducing the quantity of .csv files or the amount of
        data in the .csv files), since devices in these remaining networks are likely all
        reachable by servers that service your main Service Network.
        '''
        with open(FILE_aaa_servers) as aaaFile:
            csv_data = csv.reader(aaaFile)
            if geo_region == "REGION_A":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            elif geo_region == "REGION_B":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            elif geo_region == "REGION_C":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            elif geo_region == "REGION_D":
                for row in csv_data:
                    if row[0] == geo_region:
                        aaaServer_PRI = row[1]
                        aaaServer_SEC = row[2]
            else:
                print("ERROR! Failed to identify the optimized AAA Server IPs.")
                print("To Troubleshoot: Review the script section named: AAA and NTP Server selection\n EXITING SCRIPT...\n")
                sys.exit()

    # NTP Server selection #
    if networkType == "UNDERLAY":
        with open(FILE_ntp_servers_UNDERLAY) as ntpFile:
            csv_data = csv.reader(ntpFile)
            if geo_region == "REGION_A":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_B":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_C":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_D":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            else:
                print("ERROR! Failed to identify optimized NTP Server IPs.")
                print("To Troubleshoot: Review the script section named: AAA and NTP Server selection\n EXITING SCRIPT...\n")
                sys.exit()
    elif networkType == "UNDERLAYv2":
        with open(FILE_ntp_servers_UNDERLAYv2) as ntpFile:
            csv_data = csv.reader(ntpFile)
            if geo_region == "REGION_A":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_B":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_C":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_D":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            else:
                print("ERROR! Failed to identify optimized NTP Server IPs.")
                print("To Troubleshoot: Review the script section named: AAA and NTP Server selection\n EXITING SCRIPT...\n")
                sys.exit()
    elif networkType == "OOB":
        '''
        NOTE: You can enable/disable this section by choosing which subsection to comment
        out (Support OOB or Don't Support OOB). If you require OOB support, be sure the
        .csv file referenced below exists, and the variable the .csf file is assigned to
        at the top of this script is uncommented.
        Whatever your needs are, be sure to comment out the opposing subsection below.
        Finally, be sure your Jinja Template files can respond appropriately when OOB
        is selected as a networkType.
        '''
        # No OOB Support #
        #print(f"Determining NTP Servers for the {networkType} network is under development ATT.")
        #print("EXITING SCRIPT...")
        #sys.exit()
        #
        # OOB Support
        with open(FILE_ntp_servers_OOB) as ntpFile:
            csv_data = csv.reader(ntpFile)
            if geo_region == "REGION_A":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_B":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_C":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_D":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            else:
                print("ERROR! Failed to identify the optimized NTP Server IPs.")
                print("To Troubleshoot: Review the script section named: AAA and NTP Server selection\n EXITING SCRIPT...\n")
                sys.exit()
    else:
        with open(FILE_ntp_servers) as ntpFile:
            csv_data = csv.reader(ntpFile)
            if geo_region == "REGION_A":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_B":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_C":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            elif geo_region == "REGION_D":
                for row in csv_data:
                    if row[0] == geo_region:
                        ntpServer_Prefer = row[1]
                        ntpServer_SEC = row[2]
                        ntpServer_TER = row[3]
                        ntpServer_ALT = row[4]
            else:
                print("ERROR! Failed to identify the optimized NTP Server IPs.")
                print("To Troubleshoot: Review the script section named: AAA and NTP Server selection\n EXITING SCRIPT...\n")
                sys.exit()

    # ====================================================================================
    # Identify the site-specific, SNMP Location configuration.
    # ====================================================================================

    section_break(8)
    prompt_snmpLocation()
    snmpLocation_response = str(input("\n   Enter the Corporate Site ID:   "))
    with open (FILE_snmp_locations) as snmpFile:
        csv_data = csv.reader(snmpFile)
        snmp_loc = "No snmp location found"
        for row in csv_data:
            if snmpLocation_response in row:
                snmp_loc = row[3]
    # Verify the expected snmp syntax was extracted from the data file.
    if "snmp-server" not in snmp_loc:
        print("\n\nYour entry for [Corporate Site ID] could not be found in the database.")
        print("Contact the Corporate HQ Network Department for support.\n\nEXITING NOW...\n")
        sys.exit()

    # ====================================================================================
    # Identify the site-specific, SNMP Contact configuration.
    # ====================================================================================
    '''
    NOTE: Many organizations have the network dept at the main office manage all
    devices in the data center(s) as well as the edge devices at each branch location.
    The conditional below supplies that functionality. If this feature is unwanted,
    remove the 'if' conditional directly below the line starting the 'for' loop.
    '''
    snmpContact_response = snmpLocation_response
    with open (FILE_snmp_locations) as contactFile:
        csv_data = csv.reader(contactFile)
        for row in csv_data:
            # Ensure major WAN/DC devices are associated with the HQ Network Dept.
            if (networkType == "UNDERLAY" or networkType == "UNDERLAYv2" or
                networkType == "DATACENTER_DC" or networkType == "COMMERCIAL"):
                snmp_contact = "Corporate HQ Network Department"
            # Otherwise, conform to the contents of the data file.
            elif snmpContact_response in row:
                snmp_contact = row[4]
    # Verify the expected verbiage for SNMP Contacts was extracted from the data file.
    if "Network Department" not in snmp_contact:
        print("Failed to extract proper SNMP Contact information.")
        print("Contact the Corporate HQ Network Department for support.")
        print("\n\nEXITING NOW...\n")
        sys.exit()

    # Identify the snmp contact's phone number.
    section_break(9)
    if snmp_contact == "Corporate HQ Network Department":
        snmp_contact_phone = "REPLACE_WITH_10_DIGIT_PHONE_OF_CORPORATE_NETWORK_DEPT"
        print("\n\n\n  SNMP Contact Information Found\n\n")
    else:
        prompt_siteContactPhone(snmpContact_response)
        snmp_contact_phone = str(input(f"\n   Enter the [10-digit] Phone number:  "))

    # ====================================================================================
    # Identify the site-specific username's password for the device.
    # ====================================================================================
    '''
    NOTE: A prompt is not being used ATT since site credentials can be stored in the snmp
    data file. If you prefer a prompt to allow users to select credentials, uncomment the
    below 3 lines, then comment out the one line containing the 'sitePassword_response'
    variable assignment.
    '''
    #section_break(10)
    #prompt_sitePassword()
    #sitePassword_response = str(input("\n  Enter the Corporate Site ID (scroll up to view all sites):  "))
    sitePassword_response = snmpLocation_response
    with open (FILE_site_passwords) as passFile:
        csv_data = csv.reader(passFile)
        for row in csv_data:
            if sitePassword_response in row:
                site_password = row[1]

    # ====================================================================================
    # Identify device-specific Syslog syntax.
    # ====================================================================================
    '''
    NOTE: ATT, there is no specific syntax for the ASA config. If you prefer to have a
    custom syslog statement, feel free to replace the loggingSyntax variable in the below
    'elif' statement that references ASAs.
    '''
    # Collects from all Switches(Non-Nexus) - OVERLAY:
    if deviceType == "Switch_NON_NEXUS" and networkType == "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Routers - OVERLAY:
    elif deviceType == "Router" and networkType == "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Switches(Non-Nexus) - UNDERLAY:
    elif deviceType == "Switch_NON_NEXUS" and networkType != "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Routers - UNDERLAY:
    elif deviceType == "Router" and networkType != "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Switches(Non-Nexus) - UNDERLAYv2:
    elif deviceType == "Switch_NON_NEXUS" and networkType != "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Routers - UNDERLAYv2:
    elif deviceType == "Router" and networkType != "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Switches(Non-Nexus) - OOB:
    elif deviceType == "Switch_NON_NEXUS" and networkType != "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Routers - OOB:
    elif deviceType == "Router" and networkType != "OVERLAY":
        if vrf_exists == "y":
            loggingSyntax = f"logging host x.x.x.x vrf {vrf_name} transport udp port xxxxx"
        else:
            loggingSyntax = "logging host x.x.x.x transport udp port xxxxx"
    # Collects from all Switches - Nexus:
    elif ((deviceType == "Switch_Nexus" and networkType == "DATACENTER_DC") or
        (deviceType == "Switch_Nexus" and networkType == "OVERLAY")):
        if vrf_exists == "y":
            loggingSyntax = f"logging server x.x.x.x 6 port xxxxx use-vrf {vrf_name}"
        else:
            loggingSyntax = "logging server x.x.x.x 6 port xxxxx"
    # Collects from all ASAs:
    elif deviceType == "ASA_Traditional" or deviceType =="ASA_Firepower_21xx" or deviceType == "ASA_Firepower_21xx":
        loggingSyntax = "not_required"
    # Catch all Incompatibilities.
    else:
        print("\n\n\nERROR:   ATT, This program does not generate Syslog configs for this device-type.")
        print("\nTo troubleshoot, review the script section named:")
        print("   [Identify device-specific Syslog syntax].")
        print("\nFor support, contact Corporate HQ Network Department and notify them of this error:\n       CorporateEmail@domain.com\n")
        sys.exit()

    # ====================================================================================
    # Identify device-specific SNMP attributes.
    # ====================================================================================
    '''
    NOTE: With so many variables involved in configuring SNMP access, I found it simpler to
    manage this particular data within a data file and extract those values when needed.
    '''
    # Collects from all Routers and Switches(Non-Nexus):
    if deviceType == "Switch_NON_NEXUS" or deviceType == "Router":
        with open (FILE_snmp_users_IOS) as snmpUserFile:
            csv_data = csv.reader(snmpUserFile)
            for row in csv_data:
                if row[0] == "READuser":
                    snmp_READuser = row[1]
                    snmp_READrole = row[2]
                    snmp_READauthPW = row[3]
                    snmp_READprivPW = row[4]
                    snmp_READuserACL = row[5]
                elif row[0] == "WRITEuser":
                    snmp_WRITEuser = row[1]
                    snmp_WRITErole = row[2]
                    snmp_WRITEauthPW = row[3]
                    snmp_WRITEprivPW = row[4]
                    snmp_WRITEuserACL = row[5]
    # Collects from all Nexus Switches(non-admin contexts):
    elif deviceType == "Switch_Nexus" and vdc_type == "service":
        with open (FILE_snmp_users_NEXUS) as snmpUserFile:
            csv_data = csv.reader(snmpUserFile)
            for row in csv_data:
                if row[0] == "READuser":
                    snmp_READuser = row[1]
                    snmp_READrole = row[2]
                    snmp_READauthPW = row[3]
                    snmp_READprivPW = row[4]
                    snmp_READuserACL = row[5]
                elif row[0] == "WRITEuser":
                    snmp_WRITEuser = row[1]
                    snmp_WRITErole = row[2]
                    snmp_WRITEauthPW = row[3]
                    snmp_WRITEprivPW = row[4]
                    snmp_WRITEuserACL = row[5]
    # Collects from all Nexus Switches(admin contexts only):
    elif deviceType == "Switch_Nexus" and vdc_type == "admin":
        with open (FILE_snmp_users_NEXUS) as snmpUserFile:
            csv_data = csv.reader(snmpUserFile)
            for row in csv_data:
                if row[0] == "READuser_admin":
                    snmp_READuser = row[1]
                    snmp_READrole = row[2]
                    snmp_READauthPW = row[3]
                    snmp_READprivPW = row[4]
                    snmp_READuserACL = row[5]
                elif row[0] == "WRITEuser_admin":
                    snmp_WRITEuser = row[1]
                    snmp_WRITErole = row[2]
                    snmp_WRITEauthPW = row[3]
                    snmp_WRITEprivPW = row[4]
                    snmp_WRITEuserACL = row[5]
    # Collects from all ASAs:
    elif deviceType == "ASA_Traditional" or deviceType =="ASA_Firepower_21xx" or deviceType == "ASA_Firepower_21xx":
        with open (FILE_snmp_users_ASA) as snmpUserFile:
            csv_data = csv.reader(snmpUserFile)
            for row in csv_data:
                if row[0] == "READuser":
                    snmp_READuser = row[1]
                    snmp_READrole = row[2]
                    snmp_READauthPW = row[3]
                    snmp_READprivPW = row[4]
                    snmp_READuserACL = row[5]
                elif row[0] == "WRITEuser":
                    snmp_WRITEuser = row[1]
                    snmp_WRITErole = row[2]
                    snmp_WRITEauthPW = row[3]
                    snmp_WRITEprivPW = row[4]
                    snmp_WRITEuserACL = row[5]
    # A generic catch-all for any incompatibilities.
    else:
        print("ERROR:\nATT, This program is unable to generate SNMP-user related configs for this device-type.")
        print("To troubleshoot, review the script section named:")
        print("   [Identify device-specific SNMP attributes]")
        print("\nFor support, contact Corporate HQ Network Department and notify them of this error:\n       CorporateEmail@domain.com\n")
        sys.exit()

    # ====================================================================================
    # Data aggregation in preparation for conversion with J2 templates.
    # ====================================================================================

    print("\n\n\n"+">"*40 + 40*"<")
    print("\n"*3 + "#"*22 + "\n## AGGREGATING DATA ##\n" + "#"*22 + "\n"*3)
    input_results.append([networkType,deviceType,devName,mgmt_ipaddr,mgmt_interf,vrf_exists,vrf_name,geo_region,ise_region,aaaServer_PRI,aaaServer_SEC,ntpServer_Prefer,ntpServer_SEC,ntpServer_TER,ntpServer_ALT,snmp_loc,snmp_contact,snmp_contact_phone,site_password,loggingSyntax,snmp_READuser,snmp_READrole,snmp_READauthPW,snmp_READprivPW,snmp_READuserACL,snmp_WRITEuser,snmp_WRITErole,snmp_WRITEauthPW,snmp_WRITEprivPW,snmp_WRITEuserACL])
    print("   COMPLETED")

    # ====================================================================================
    # Prepare and load the Jinja2 templating environment.
    # ====================================================================================
    '''
    NOTE: If a specific Jinja2 template is not production-ready, in this section you can
    force the application to stop processing for that particular template(s) and exit.
    This allows the app to continue to function while you test.
    '''
    print("\n"*3 + "#"*35 + "\n## SELECTING THE PROPER TEMPLATE ##\n" + "#"*35 + "\n"*3)

    # Identify and load the Jinja2 template directory.
    file_loader = FileSystemLoader('./Jinja_Templates')

    # Load the appropriate Jinja environment.
    environ = Environment(loader=file_loader)

    # Assign the correct STIG template.
    if (("Router" in input_results[0]) or ("Switch_NON_NEXUS" in input_results[0])):
        #############################
        # Comment this section b/w the 2 long hash signs, and uncomment the 3 lines following it, once the IOS-XE J2 Template(s) is completed.
        #print("The IOS and IOS-XE template is not complete ATT\nPlease try again later.")
        #print("\nFor support, contact Corporate HQ Network Department:\n    CorporateEmail@domain.com")
        #print("\n\nEXITING SCRIPT...\n")
        #sys.exit()
        #############################
        template = environ.get_template(JINJA_TEMPLATE_IOS_IOSXE)
        print("Successfully loaded:\n - Jinja environment\n - IOS/IOS-XE template.\n\n\n")
        print("   COMPLETED")
    elif "Switch_Nexus" in input_results[0]:
        # Comment out the below section b/w the 2 long hash signs, and uncomment the 3 lines following it, once the NX J2 Template(s) is completed.
        #############################
        #print("The Nexus Switch template is not complete ATT\nPlease try again later.")
        #print("\nFor support, contact Corporate HQ Network Department:\n    CorporateEmail@domain.com")
        #print("\n\nEXITING SCRIPT...\n")
        #sys.exit()
        #############################
        template = environ.get_template(JINJA_TEMPLATE_NEXUS)
        print("Successfully loaded:\n - Jinja environment\n - NEXUS template.\n\n\n")
        print("   COMPLETED")
    elif "ASA_Traditional" in input_results[0] or "ASA_Firepower_21xx" in input_results[0] or "ASA_Firepower_21xx" in input_results[0]:
        # Comment out the below section b/w the 2 long hash signs, and uncomment the 3 lines following it, once the ASA J2 Template(s) is completed.
        #############################
        print("The ASA template is not complete ATT\nPlease try again later.")
        print("\nFor support, contact Corporate HQ Network Department:\n    CorporateEmail@domain.com")
        print("\n\nEXITING SCRIPT...\n")
        sys.exit()
        #############################
        #template = environ.get_template(JINJA_TEMPLATE_ASA)
        #print("Successfully loaded:\n - Jinja environment\n - ASA template.\n\n\n")
        #print("   COMPLETED")
    else:
        print("\nERROR:\n   Could not determine the correct Jinja template after analyzing deviceType!") 
        print("No STIG Config File will be generated.\n\nReview the Section labeled:")
        print("   Prepare and load the Jinja2 templating environment.\n\n")
        print("For support, contact Corporate HQ Network Department:\n    CorporateEmail@domain.com")
        print("\n\nEXITING SCRIPT...\n")
        sys.exit()

    # ====================================================================================
    # Rendor STIG Config. See all exportable VARS below:
    # ====================================================================================
    # [networkType]      [deviceType]       [devName]          [mgmt_ipaddr]      [mgmt_interf]
    # [vrf_exists]       [vrf_name]         [geo_region]       [ise_region]       [aaaServer_PRI]
    # [aaaServer_SEC]    [ntpServer_Prefer] [ntpServer_SEC]    [ntpServer_TER]    [ntpServer_ALT] 
    # [snmp_loc]         [site_password]    [loggingSyntax]    [snmp_READuser]    [snmp_READrole] 
    # [snmp_READauthPW]  [snmp_READprivPW]  [snmp_READuserACL] [snmp_WRITEuser]   [snmp_WRITErole]
    # [snmp_WRITEauthPW] [snmp_WRITEprivPW] [snmp_WRITEuserACL] [snmp_contact] [snmp_contact_phone]
    # ====================================================================================

    # Use available VARS to rendor the device config based on the selected Jinja Template.
    print("\n"*3 + "#"*27 + "\n## RENDORING STIG CONFIG ##\n" + "#"*27 + "\n"*3)
    #try:
    output = template.render(networkType = networkType,
                            devType = deviceType,
                            hostname = devName,
                            mgmt_IP = mgmt_ipaddr,
                            mgmt_Int = mgmt_interf,
                            vrf_check = vrf_exists,
                            vrf_name = vrf_name,
                            AAA_PRI = aaaServer_PRI,
                            AAA_SEC = aaaServer_SEC,
                            NTP_1 = ntpServer_Prefer,
                            NTP_2 = ntpServer_SEC,
                            NTP_3 = ntpServer_TER,
                            NTP_4 = ntpServer_ALT,
                            snmp_location = snmp_loc,
                            snmp_contact = snmp_contact,
                            snmp_contact_phone = snmp_contact_phone,
                            sitePass = site_password,
                            syslogSyntax = loggingSyntax,
                            snmp_READuser = snmp_READuser,
                            snmp_READrole = snmp_READrole,
                            snmp_READauthPW = snmp_READauthPW,
                            snmp_READprivPW = snmp_READprivPW,
                            snmp_READuserACL = snmp_READuserACL,
                            snmp_WRITEuser = snmp_WRITEuser,
                            snmp_WRITErole = snmp_WRITErole,
                            snmp_WRITEauthPW = snmp_WRITEauthPW,
                            snmp_WRITEprivPW = snmp_WRITEprivPW,
                            snmp_WRITEuserACL = snmp_WRITEuserACL)
    #except Exception:
    #    print("\nERROR:\nThe Base STIG Config File could NOT be rendered.\nReview the Script Section labeled:")
    #    print("   Rendor STIG Config.\n\n")
    #    print("For support, contact Corporate HQ Network Department:\n    CorporateEmail@domain.com")
    #    print("\n\nEXITING SCRIPT...\n")
    #    sys.exit()
    print("   COMPLETED")

    # Save the rendored config as an exportable file.
    print("\n"*3 + "#"*34 + "\n## SAVING STIG CONFIG AS A FILE ##\n" + "#"*34 + "\n"*3)
    with open(STIG_config_abs_path,"w") as genFile:
        genFile.write(output)
    print("\n   SAVE SUCCESSFUL")

    # [OPTIONAL] Display the config in the terminal.
    view_response = str(input(f"\n\n\nView the Base STIG Config for  [{devName}]  in the terminal now?\n  Response [y/n]:  "))
    if view_response.lower() == "y":
        print("\n"*3)
        print(output)
        print("\n"*3 + "#"*65 + "\n" + "#"*65 + f"\n   CONFIGURATION COMPLETED FOR: [{devName}]  ({mgmt_ipaddr})\n" + "#"*65 + "\n" + "#"*65 + "\n"*3)
        print(f"  The Configuration file is:  {STIG_config_filename}")
        print(f"              File location:  {STIG_config_abs_path}")
        print("\n\nCAUTION:   DO NOT boot from this file!\n\n")
        print(" - Ensure you have level 15 privileges, then copy+paste it to the running config within a console or VTY session.")
        print(f" - After applying the config, contact Corporate HQ Network Department and request [{mgmt_ipaddr}] be configured for [{devName}] in the Corporate TACACS Server.")
    else:
        print("\n"*3 + "#"*65 + "\n" + "#"*65 + f"\n   CONFIGURATION COMPLETED FOR: [{devName}]  ({mgmt_ipaddr})\n" + "#"*65 + "\n" + "#"*65 + "\n"*3)
        print(f"  The Configuration file is:  {STIG_config_filename}")
        print(f"              File location:  {STIG_config_abs_path}")
        print("\n\nCAUTION:   DO NOT boot from this file!\n\n")
        print(" - Ensure you have level 15 privileges, then copy+paste it to the running config within a console or VTY session.")
        print(f" - After applying the config, contact Corporate HQ Network Department and request [{mgmt_ipaddr}] be configured for [{devName}] in the Corporate TACACS Server.")

# ========================================================================================
#
#         `````*****<<<<<-----_____  Begin File Mode  _____----->>>>>*****`````
#
# ========================================================================================

elif mode_prompt == "2":
    print("\n\n\n___FILE MODE___\n\n")
    print("\nEnter the name of the file. [To perform a test run using your templates with real sample data, enter:  dryrun]")
    filemode_source = file_mode_path + input("  Filename:  ")
    if filemode_source.__contains__("dryrun"):
        filemode_source = example_FILE
    if not os.path.exists(filemode_source):
        print("Your entry was NOT found!")
        sys.exit()
    if not os.path.isfile(filemode_source):
        print("Your entry is NOT a file!")
        sys.exit()
    with open (filemode_source) as inputFile:
#
#    with open (filemode_source, newline='') as inputFile:
#
        csv_data = csv.reader(inputFile)
        for row in csv_data:
            print("\n"*3 + "#"*39 + "\n### NEW ROW IN FILE: REVIEWING DATA ###\n" + "#"*39)
            networkType = row[0]
            deviceType = row[1]
            devName = row[2]
            mgmt_ipaddr = row[3]
            mgmt_interf = row[4]
            vrf_exists = row[5]
            vrf_name = row[6]
            aaaServer_PRI = row[9]
            aaaServer_SEC = row[10]
            ntpServer_Prefer = row[11]
            ntpServer_SEC = row[12]
            ntpServer_TER = row[13]
            ntpServer_ALT = row[14]
            snmp_loc = row[15]
            snmp_contact = row[16]
            snmp_contact_phone = row[17]
            site_password = row[18]
            loggingSyntax = row[19]
            snmp_READuser = row[20]
            snmp_READrole = row[21]
            snmp_READauthPW = row[22]
            snmp_READprivPW = row[23]
            snmp_READuserACL = row[24]
            snmp_WRITEuser = row[25]
            snmp_WRITErole = row[26]
            snmp_WRITEauthPW = row[27]
            snmp_WRITEprivPW = row[28]
            snmp_WRITEuserACL = row[29]
            input_results.clear()
            input_results.append([networkType,deviceType,devName,mgmt_ipaddr,mgmt_interf,vrf_exists,vrf_name,aaaServer_PRI,aaaServer_SEC,ntpServer_Prefer,ntpServer_SEC,ntpServer_TER,ntpServer_ALT,snmp_loc,snmp_contact,snmp_contact_phone,site_password,loggingSyntax,snmp_READuser,snmp_READrole,snmp_READauthPW,snmp_READprivPW,snmp_READuserACL,snmp_WRITEuser,snmp_WRITErole,snmp_WRITEauthPW,snmp_WRITEprivPW,snmp_WRITEuserACL])
            print("\n\n\n   COMPLETED\n")

            # Create file and file location VARS.
            STIG_config_filename = stig_config_file_PREFIX + devName
            STIG_config_abs_path = stig_config_file_path + STIG_config_filename

            # Prepare and load the appropriate Jinja2 templating environment.
            print("\n"*2 + "#"*35 + "\n## SELECTING THE PROPER TEMPLATE ##\n" + "#"*35 + "\n"*2)

            # Identify and load the Jinja2 template directory.
            file_loader = FileSystemLoader('./Jinja_Templates')

            # Load the appropriate Jinja environment.
            environ = Environment(loader=file_loader)

            # Assign the correct STIG template.
            if (("Router" in input_results[0][1]) or ("Switch_NON_NEXUS" in input_results[0][1])):
                # Comment out the below section b/w the 2 long hash signs, and uncomment the 3 lines following it, once the IOS-XE J2 Template(s) is completed.
                #############################
                #print("The IOS-XE template is not complete ATT\nPlease try again later.")
                #print("To troubleshoot, review the script section named:")
                #print("   [Assign the correct STIG template] underneath [Begin File Mode Script]")
                #print("\nFor support, contact Corporate HQ Network Department and notify them of this error:\n       CorporateEmail@domain.com\n")
                #print("\n\nEXITING SCRIPT...\n")
                #sys.exit()
                #############################
                template = environ.get_template(JINJA_TEMPLATE_IOS_IOSXE)
                print("Successfully loaded:\n - Jinja environment\n - IOS/IOS-XE template.\n\n\n")
                print("   COMPLETED")
            elif "Switch_Nexus" in input_results[0][1]:
                # Comment out the below section b/w the 2 long hash signs, and uncomment the 3 lines following it, once the NX J2 Template(s) is completed.
                #############################
                #print("The Nexus Switch template is not complete ATT\nPlease try again later.")
                #print("To troubleshoot, review the script section named:")
                #print("   [Assign the correct STIG template] underneath [Begin File Mode Script]")
                #print("\nFor support, contact Corporate HQ Network Department and notify them of this error:\n       CorporateEmail@domain.com\n")
                #print("\n\nEXITING SCRIPT...\n")
                #sys.exit()
                #############################
                template = environ.get_template(JINJA_TEMPLATE_NEXUS)
                print("Successfully loaded:\n - Jinja environment\n - Nexus Switch template.\n\n\n")
                print("   COMPLETED")
            elif "ASA_Traditional" in input_results[0][1] or "ASA_Firepower_21xx" in input_results[0][1] or "ASA_Firepower_21xx" in input_results[0][1]:
                # Comment out the below section b/w the 2 long hash signs, and uncomment the 3 lines following it, once the ASA J2 Template(s) is completed.
                #############################
                print("The ASA template is not complete ATT\nPlease try again later.")
                print("To troubleshoot, review the script section named:")
                print("   [Assign the correct STIG template] underneath [Begin File Mode Script]")
                print("\nFor support, contact Corporate HQ Network Department and notify them of this error:\n       CorporateEmail@domain.com\n")
                print("\n\nEXITING SCRIPT...\n")
                sys.exit()
                #############################
                #template = environ.get_template(JINJA_TEMPLATE_ASA)
                #print("Successfully loaded:\n - Jinja environment\n - ASA template.\n\n\n")
                #print("   COMPLETED")
            else:
                print("\nERROR:\n   Could not determine the correct Jinja template after analyzing deviceType!") 
                print("No STIG Config File will be generated.\n\nReview the Section labeled:")
                print("   Begin File Mode Script.\n\n EXITING SCRIPT...\n")
                sys.exit()

            # ============================================================================
            # Rendor STIG Config. See all exportable VARS below:
            # ============================================================================
            # [networkType]      [deviceType]       [devName]          [mgmt_ipaddr]      [mgmt_interf]
            # [vrf_exists]       [vrf_name]         [geo_region]       [ise_region]       [aaaServer_PRI]
            # [aaaServer_SEC]    [ntpServer_Prefer] [ntpServer_SEC]    [ntpServer_TER]    [ntpServer_ALT] 
            # [snmp_loc]         [site_password]    [loggingSyntax]    [snmp_READuser]    [snmp_READrole] 
            # [snmp_READauthPW]  [snmp_READprivPW]  [snmp_READuserACL] [snmp_WRITEuser]   [snmp_WRITErole]
            # [snmp_WRITEauthPW] [snmp_WRITEprivPW] [snmp_WRITEuserACL] [snmp_contact] [snmp_contact_phone]
            # ============================================================================

            # Use available VARS to rendor the device config based on the selected Jinja Template.
            print("\n"*3 + "#"*27 + "\n## RENDORING STIG CONFIG ##\n" + "#"*27 + "\n"*3)
            output = template.render(networkType = networkType,
                            devType = deviceType,
                            hostname = devName,
                            mgmt_IP = mgmt_ipaddr,
                            mgmt_Int = mgmt_interf,
                            vrf_check = vrf_exists,
                            vrf_name = vrf_name,
                            AAA_PRI = aaaServer_PRI,
                            AAA_SEC = aaaServer_SEC,
                            NTP_1 = ntpServer_Prefer,
                            NTP_2 = ntpServer_SEC,
                            NTP_3 = ntpServer_TER,
                            NTP_4 = ntpServer_ALT,
                            snmp_location = snmp_loc,
                            snmp_contact = snmp_contact,
                            snmp_contact_phone = snmp_contact_phone,
                            sitePass = site_password,
                            syslogSyntax = loggingSyntax,
                            snmp_READuser = snmp_READuser,
                            snmp_READrole = snmp_READrole,
                            snmp_READauthPW = snmp_READauthPW,
                            snmp_READprivPW = snmp_READprivPW,
                            snmp_READuserACL = snmp_READuserACL,
                            snmp_WRITEuser = snmp_WRITEuser,
                            snmp_WRITErole = snmp_WRITErole,
                            snmp_WRITEauthPW = snmp_WRITEauthPW,
                            snmp_WRITEprivPW = snmp_WRITEprivPW,
                            snmp_WRITEuserACL = snmp_WRITEuserACL)
            print("   COMPLETED")

            # Save the rendored config as an exportable file.
            print("\n"*3 + "#"*34 + "\n## SAVING STIG CONFIG AS A FILE ##\n" + "#"*34 + "\n"*3)
            with open(STIG_config_abs_path,"w") as genFile:
                genFile.write(output)
            print("   SAVE SUCCESSFUL")

            # [OPTIONAL] Display the config in the terminal.
            view_response = str(input(f"\n\n\n View the Base STIG Config for  [{devName}]  in the terminal now?\n  Response [y/n]:  "))
            if view_response.lower() == "y":
                print("\n"*3)
                print(output)
                print("\n"*3 + "#"*65 + "\n" + "#"*65 + f"\n   CONFIGURATION COMPLETED FOR:  [{devName}]  ({mgmt_ipaddr})\n" + "#"*65 + "\n" + "#"*65 + "\n"*3)
                print(f"  The Configuration file is:  {STIG_config_filename}")
                print(f"              File location:  {STIG_config_abs_path}")
                print("\n\nCAUTION:   DO NOT boot from this file!\n\n")
                print(" - Ensure you have level 15 privileges, then copy+paste it to the running config within a console or VTY session.")
                print(f" - After applying the config, contact Corporate HQ Network Department and request [{mgmt_ipaddr}] be configured for [{devName}] in the Corporate TACACS server.")
            else:
                print("\n"*3 + "#"*65 + "\n" + "#"*65 + f"\n   CONFIGURATION COMPLETED FOR:  [{devName}]  ({mgmt_ipaddr})\n" + "#"*65 + "\n" + "#"*65 + "\n"*3)
                print(f"  The Configuration file is:  {STIG_config_filename}")
                print(f"              File location:  {STIG_config_abs_path}")
                print("\n\nCAUTION:   DO NOT boot from this file!\n\n")
                print(" - Ensure you have level 15 privileges, then copy+paste it to the running config within a console or VTY session.")
                print(f" - After applying the config, contact Corporate HQ Network Department and request [{mgmt_ipaddr}] be configured for [{devName}] in the Corporate TACACS server.")

# ========================================================================================
# Handle unexpected response from user input during the initial prompt to Choose a Mode.
# ========================================================================================

else:
    print("\nYou entered an invalid response!")
    print("\n"*3 + "#"*25 + "\n### Exiting Program.. ###\n" + "#"*25 + "\n"*3)
    sys.exit()

# ========================================================================================
# Exit Program.
# ========================================================================================

print("\n"*3 + "#"*23 + "\n### Exiting Program ###\n" + "#"*23 + "\n"*3)
sys.exit()
