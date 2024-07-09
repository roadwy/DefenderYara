
rule PWS_Win32_Zbot_GOY_bit{
	meta:
		description = "PWS:Win32/Zbot.GOY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 1f 33 c1 c1 e9 08 0f b6 c0 33 0c 85 ?? ?? ?? ?? 47 3b fa 72 e8 } //1
		$a_03_1 = {6a 20 5a 8d 4c 24 ?? e8 ?? ?? ?? ?? 31 44 34 ?? 83 c6 04 3b f2 72 e9 } //1
		$a_03_2 = {8b c1 83 e0 03 8a 44 04 ?? 30 44 0c ?? 41 83 f9 08 72 ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule PWS_Win32_Zbot_GOY_bit_2{
	meta:
		description = "PWS:Win32/Zbot.GOY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 18 8a c3 2c 61 3c 19 77 03 80 c3 e0 c1 c9 0d 0f b6 c3 03 c8 47 8d 04 7e 66 39 28 75 e2 } //1
		$a_03_1 = {4c 69 62 72 c7 44 24 ?? 61 72 79 41 88 44 24 ?? c7 44 24 ?? 47 65 74 50 c7 44 24 ?? 72 6f 63 41 c7 44 24 ?? 64 64 72 65 66 c7 44 ?? 30 73 73 88 44 24 } //1
		$a_03_2 = {0f b7 14 8f bb 19 04 00 00 66 3b d3 0f 84 ?? 00 00 00 83 c3 09 66 3b d3 0f 84 ?? 00 00 00 bb 23 04 00 00 66 3b d3 0f 84 ?? 00 00 00 83 c3 1c 66 3b d3 0f 84 ?? 00 00 00 41 3b c8 72 } //1
		$a_03_3 = {83 f8 01 75 04 6a 06 eb 62 3b c1 75 04 6a 09 eb 5a 83 f8 03 75 6d 6a 0b eb 51 83 bd ?? ?? ?? ?? 0a 75 60 6a 0c eb 44 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}