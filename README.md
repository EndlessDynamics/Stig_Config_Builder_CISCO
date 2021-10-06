# Stig_Config_Builder_CISCO

WHAT:
   A single python script that allows for the auto-generation of custom configuration template files for the purpose of ensuring secure, baseline running configurations on a variety of Cisco platforms.

WHY:
   Have you ever encountered a situation where new security baselines have been defined and you and your team need to make changes to the ENTIRE network? Well this simplifies the laborious and manual task of reviewing and reconfiguring each of your devices to meet any newly required standards. This single script can handle that process for you in a safe way in which you can copy+paste the new baseline configurations directly into an existing device config without fear of being "locked out" of the device or interupting the data plane.

DISCLAIMER:
   By using this script and the generated device configurations templates, you accept full responsibility for any changes to device configurations. As with most professional organizations, you and your organization are solely responsible for reviewing ANY device configuration and accepting the resulting changes(if any) before applying them to any device on a network; and the generated config from this script is, of course, no exception to that.

Current Release: Version 1.4.2


## Requirements

- Python3 (v3.7 or higher)
   - Currently tested on: 3.7.3, 3.8.3, 3.8.7
- Jinja2 (v2.11.3 or higher)
   - Currently tested on: 2.11.3, 3.0.1


### Requirements.txt

- Download the requirements.txt file to use for your environment.

Pip Freeze Content:
Jinja2==3.0.1
MarkupSafe==2.0.1

Pip List Content:
Package    Version
---------- -------
Jinja2     3.0.1
MarkupSafe 2.0.1
pip        21.2.4
setuptools 58.2.0
wheel      0.37.0

## Planned Future Releases

- Version 2.0.0
   - Simplify management of customizable STIG data by consolidating all individual STIG data csv files into one csv file. Proper data extraction will be performed by identifying datasets via k:v.

- Version 2.2.0
   - Introduce additional, more advanced, base config capabilities for Cisco NX-OS platforms.

- Version 2.3.0
   - Introduce additional, more advanced, base config capabilities for Cisco ASA platforms.

- Version 3.x.0
   - Introduce base config capabilities for Cisco Firepower 2100 series and 4100 series appliances.

- Version ?.x
   - Fork this script and incorporate automated and continuous extraction of device data from multiple paid-for and open-source DCIM/IT-Asset solutions, such as:
     + Nautobot
     + NetBox (v3.0 and greater)
     + Cisco Identity Services Engine(ISE) (v2.7 and greater)
     + Infoblox NetMRI
     + YAML-based inventory file


# Questions, Comments, Ideas?

   Join my Discussions page and leave your thoughts for the community and I to see!
