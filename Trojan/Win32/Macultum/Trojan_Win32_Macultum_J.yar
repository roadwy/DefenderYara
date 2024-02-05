
rule Trojan_Win32_Macultum_J{
	meta:
		description = "Trojan:Win32/Macultum.J,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 77 69 6e 63 6f 6d 70 75 74 65 00 } //01 00 
		$a_01_1 = {00 77 69 6e 2d 63 6f 6d 70 75 74 65 00 } //0a 00 
		$a_01_2 = {00 62 6c 64 00 74 62 73 00 2e 63 00 00 6f 6d 00 } //0a 00 
		$a_01_3 = {62 6c 64 74 62 73 2e 63 6f 6d 2f } //0a 00 
		$a_01_4 = {28 73 6f 63 6b 73 7c 68 74 74 70 29 3d 28 5b 5e 3a 5d 2b 29 3a 28 5c 64 2b 29 } //00 00 
	condition:
		any of ($a_*)
 
}