
rule Trojan_Win32_AccountDiscovery_G{
	meta:
		description = "Trojan:Win32/AccountDiscovery.G,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 00 73 00 71 00 75 00 65 00 72 00 79 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_1 = {64 00 73 00 67 00 65 00 74 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}