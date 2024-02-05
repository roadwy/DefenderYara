
rule Trojan_Win32_Flyhigh_A{
	meta:
		description = "Trojan:Win32/Flyhigh.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {70 00 61 00 74 00 68 00 20 00 65 00 78 00 63 00 65 00 6c 00 3a 00 20 00 90 02 20 5c 00 78 00 6c 00 73 00 90 02 08 2e 00 78 00 6c 00 73 00 78 00 90 00 } //01 00 
		$a_00_1 = {78 6c 41 75 74 6f 4f 70 65 6e 00 } //01 00 
		$a_01_2 = {33 c0 66 ad 03 c2 ab 49 75 f6 } //02 00 
		$a_03_3 = {8d 40 ff 83 e9 01 75 f8 90 0a 20 00 b8 02 10 00 00 b9 c4 0f 00 00 90 00 } //02 00 
		$a_03_4 = {68 30 bd 00 00 68 90 01 04 56 e8 90 01 03 00 83 c4 0c ff d6 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 23 
	condition:
		any of ($a_*)
 
}