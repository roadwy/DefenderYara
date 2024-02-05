
rule Trojan_Win32_Adload_EA{
	meta:
		description = "Trojan:Win32/Adload.EA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {be 00 40 00 00 8d 90 01 03 b8 ff 00 00 00 e8 90 01 04 88 03 43 4e 75 f0 8d 90 01 03 b9 00 40 00 00 8b 90 01 02 8b 18 ff 53 10 4f 75 d3 90 00 } //01 00 
		$a_00_1 = {2e 61 73 61 69 63 61 63 68 65 2e 63 6f 6d 3a } //01 00 
		$a_00_2 = {2e 68 65 74 6f 64 6f 2e 63 6f 6d 3a } //01 00 
		$a_00_3 = {5f 63 68 2e 70 68 70 3f 75 69 64 3d 25 73 } //01 00 
		$a_00_4 = {2f 72 65 2e 70 68 70 3f 6b 65 79 3d 25 73 26 76 65 72 3d 25 73 26 75 69 64 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}