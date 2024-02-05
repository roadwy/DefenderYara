
rule Trojan_Win32_AccountDiscovery_E{
	meta:
		description = "Trojan:Win32/AccountDiscovery.E,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 6b 00 65 00 79 00 } //01 00 
		$a_00_1 = {76 00 61 00 75 00 6c 00 74 00 63 00 6d 00 64 00 } //ff ff 
		$a_00_2 = {2e 00 6e 00 65 00 74 00 } //ff ff 
		$a_00_3 = {2f 00 61 00 64 00 64 00 } //ff ff 
		$a_00_4 = {2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}