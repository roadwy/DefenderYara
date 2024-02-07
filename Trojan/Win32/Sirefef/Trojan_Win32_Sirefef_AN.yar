
rule Trojan_Win32_Sirefef_AN{
	meta:
		description = "Trojan:Win32/Sirefef.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 64 69 73 63 74 90 01 01 3d 73 65 6e 64 90 00 } //01 00 
		$a_01_1 = {33 c0 89 06 89 46 04 89 46 08 89 46 0c 89 46 10 89 46 18 c7 46 1c 63 6e 63 74 } //01 00 
		$a_01_2 = {26 61 69 64 3d 25 75 } //00 00  &aid=%u
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_AN_2{
	meta:
		description = "Trojan:Win32/Sirefef.AN,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 64 69 73 63 74 90 01 01 3d 73 65 6e 64 90 00 } //01 00 
		$a_01_1 = {33 c0 89 06 89 46 04 89 46 08 89 46 0c 89 46 10 89 46 18 c7 46 1c 63 6e 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}