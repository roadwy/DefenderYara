
rule Worm_Win32_Gamarue_PLE_{
	meta:
		description = "Worm:Win32/Gamarue.PLE!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 00 7d 00 2c 00 7b 00 22 00 74 00 22 00 3a 00 25 00 6c 00 75 00 2c 00 22 00 70 00 22 00 3a 00 22 00 25 00 73 00 22 00 2c 00 22 00 63 00 22 00 3a 00 22 00 25 00 73 00 25 00 73 00 22 00 2c 00 22 00 64 00 22 00 3a 00 22 00 25 00 73 00 } //01 00  "},{"t":%lu,"p":"%s","c":"%s%s","d":"%s
		$a_01_1 = {2c 22 6b 6c 22 3a 22 } //01 00  ,"kl":"
		$a_00_2 = {83 c4 0c 83 e9 05 c6 00 e9 89 48 01 8d 45 14 50 6a 40 57 56 ff d3 85 c0 74 2b 8b 45 0c 2b c6 83 e8 05 89 46 01 8d 45 14 50 ff 75 14 c6 06 e9 57 56 ff d3 } //00 00 
	condition:
		any of ($a_*)
 
}