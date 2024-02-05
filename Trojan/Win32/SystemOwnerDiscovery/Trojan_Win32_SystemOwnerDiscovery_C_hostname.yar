
rule Trojan_Win32_SystemOwnerDiscovery_C_hostname{
	meta:
		description = "Trojan:Win32/SystemOwnerDiscovery.C!hostname,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 } //f6 ff 
		$a_00_2 = {2f 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 } //f6 ff 
		$a_00_3 = {2d 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 } //f6 ff 
		$a_00_4 = {6c 00 6d 00 68 00 6f 00 73 00 74 00 69 00 64 00 2e 00 65 00 78 00 65 00 } //f6 ff 
		$a_00_5 = {45 00 58 00 45 00 43 00 55 00 54 00 49 00 4f 00 4e 00 5f 00 48 00 4f 00 53 00 54 00 4e 00 41 00 4d 00 45 00 } //00 00 
	condition:
		any of ($a_*)
 
}