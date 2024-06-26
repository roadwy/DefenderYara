
rule PWS_Win32_Fareit_P_MTB{
	meta:
		description = "PWS:Win32/Fareit.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 44 24 18 46 a3 90 01 04 c1 e8 90 01 01 30 44 3e ff 3b f3 7c 90 09 1b 00 a1 90 01 04 c7 44 24 18 90 01 04 81 44 24 18 90 01 04 69 c0 90 00 } //01 00 
		$a_02_1 = {03 04 24 8b c8 a3 90 01 04 8b 44 24 08 c1 e9 90 01 01 30 08 90 09 19 00 a1 90 01 04 c7 04 24 90 01 04 81 04 24 90 01 04 69 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Fareit_P_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 0c 28 0f b6 54 28 01 88 4c 24 11 0f b6 4c 28 02 8a 44 28 03 88 54 24 12 8d 54 24 11 52 8d 74 24 17 8d 7c 24 16 88 4c 24 17 e8 90 01 04 0f b6 4c 24 15 8b 44 24 18 0f b6 54 24 16 88 0c 03 0f b6 4c 24 17 88 54 03 01 8b 54 24 20 88 4c 03 02 83 c5 90 01 01 83 c4 90 01 01 83 c3 90 01 01 3b 2a 72 90 09 05 00 a1 90 00 } //01 00 
		$a_02_1 = {8b 44 24 0c 01 44 24 04 89 0c 24 c1 24 24 04 01 14 24 03 4c 24 10 89 4c 24 10 8b 44 24 10 31 04 24 8b 44 24 04 31 04 24 8b 04 24 83 c4 90 01 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}