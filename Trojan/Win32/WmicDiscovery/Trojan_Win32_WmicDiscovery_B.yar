
rule Trojan_Win32_WmicDiscovery_B{
	meta:
		description = "Trojan:Win32/WmicDiscovery.B,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 32 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 } //0a 00  WMIC.exe
		$a_00_1 = {64 00 73 00 5f 00 67 00 72 00 6f 00 75 00 70 00 20 00 77 00 68 00 65 00 72 00 65 00 } //0a 00  ds_group where
		$a_00_2 = {64 00 73 00 5f 00 73 00 61 00 6d 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 6e 00 61 00 6d 00 65 00 } //0a 00  ds_samaccountname
		$a_00_3 = {44 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 41 00 64 00 6d 00 69 00 6e 00 73 00 } //0a 00  Domain Admins
		$a_00_4 = {47 00 65 00 74 00 20 00 64 00 73 00 5f 00 6d 00 65 00 6d 00 62 00 65 00 72 00 } //00 00  Get ds_member
	condition:
		any of ($a_*)
 
}