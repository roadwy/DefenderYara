
rule Worm_Win32_Phorpiex_AB{
	meta:
		description = "Worm:Win32/Phorpiex.AB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 0c 56 ff d3 8b 3d 90 01 04 6a 64 ff d7 6a 00 6a 0d 68 00 01 00 00 56 ff d3 6a 64 ff d7 6a 00 68 90 01 04 ff d5 5f 85 c0 90 00 } //01 00 
		$a_01_1 = {bb 20 03 00 00 eb 03 8d 49 00 6a 00 6a 26 68 00 01 00 00 56 ff d7 83 eb 01 75 ef } //01 00 
		$a_01_2 = {74 53 6b 4d 61 69 6e 46 6f 72 6d 2e 55 6e 69 63 6f 64 65 43 6c 61 73 73 } //01 00  tSkMainForm.UnicodeClass
		$a_03_3 = {5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c 53 6b 79 70 65 72 90 02 03 5c 52 65 6c 65 61 73 65 5c 53 6b 79 70 65 2e 70 64 62 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 05 
	condition:
		any of ($a_*)
 
}