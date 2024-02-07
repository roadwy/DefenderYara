
rule Trojan_Win32_Badappx_A{
	meta:
		description = "Trojan:Win32/Badappx.A,SIGNATURE_TYPE_PEHSTR,ffffffdc 00 ffffffdc 00 05 00 00 64 00 "
		
	strings :
		$a_01_0 = {77 73 75 2a 2e 74 6d 70 } //64 00  wsu*.tmp
		$a_01_1 = {50 6c 61 63 65 68 6f 6c 64 65 72 54 69 6c 65 4c 6f 67 6f 46 6f 6c 64 65 72 } //14 00  PlaceholderTileLogoFolder
		$a_01_2 = {5c 00 3f 00 3f 00 5c 00 63 00 3a 00 } //14 00  \??\c:
		$a_01_3 = {5c 00 3f 00 3f 00 5c 00 64 00 3a 00 } //14 00  \??\d:
		$a_01_4 = {5c 00 3f 00 3f 00 5c 00 65 00 3a 00 } //00 00  \??\e:
	condition:
		any of ($a_*)
 
}