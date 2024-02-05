
rule Worm_Win32_Cutwail_A{
	meta:
		description = "Worm:Win32/Cutwail.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {68 24 00 07 00 57 ff 15 90 01 04 57 8b d8 ff 15 90 01 04 3b de 75 0b ff 15 90 01 04 83 f8 13 75 0f } //03 00 
		$a_02_1 = {89 45 f0 46 83 fe 1a 0f 82 90 01 01 ff ff ff 90 00 } //03 00 
		$a_01_2 = {30 62 75 6c 6b 6e 65 74 5c 46 4c 41 53 48 5c } //02 00 
		$a_01_3 = {47 6c 6f 62 61 6c 5c 46 6c 61 73 68 } //01 00 
		$a_01_4 = {25 73 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_01_5 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 25 73 3a 5c } //00 00 
	condition:
		any of ($a_*)
 
}