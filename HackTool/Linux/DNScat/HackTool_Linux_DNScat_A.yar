
rule HackTool_Linux_DNScat_A{
	meta:
		description = "HackTool:Linux/DNScat.A,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {2e 2f 64 6e 73 63 61 74 20 2d 2d 64 6e 73 20 64 6f 6d 61 69 6e 3d 73 6b 75 6c 6c 73 65 63 6c 61 62 73 2e 6f 72 67 2c 73 65 72 76 65 72 3d } //02 00  ./dnscat --dns domain=skullseclabs.org,server=
		$a_00_1 = {65 6e 63 72 79 70 74 65 64 20 73 65 73 73 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 21 20 46 6f 72 20 61 64 64 65 64 20 73 65 63 75 72 69 74 79 2c 20 70 6c 65 61 73 65 20 76 65 72 69 66 79 } //02 00  encrypted session established! For added security, please verify
		$a_00_2 = {53 74 61 72 74 69 6e 67 3a 20 2f 62 69 6e 2f 73 68 20 2d 63 } //00 00  Starting: /bin/sh -c
	condition:
		any of ($a_*)
 
}