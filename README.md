pynecogc
=========

Python network config generator and checker. 


Generates configuration for Cisco and Comware platforms, based on information stored in a xml file. Also modifies ncat configuration template (written in mako) in order to get a tailored config for the particular device (so basically replaces ncat_config) which can be then used to check the devices configurations for compliance with best practises or a company's security policy. 
