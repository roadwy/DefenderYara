
rule TrojanSpy_Win32_Hitpop_AG{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AG,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 7d f8 00 0f 84 90 01 02 00 00 8b 45 f8 8a 18 80 fb 25 0f 85 90 01 02 00 00 8b 45 f8 80 78 01 75 75 7d 8d 45 f4 50 b9 06 00 00 00 ba 01 00 00 00 8b 45 f8 e8 90 09 07 00 6a 01 e8 90 00 } //1
		$a_03_1 = {0f b6 54 3a ff 33 c2 89 45 f8 8d 45 dc 8b 55 f8 e8 90 01 04 8b 55 dc 8b c6 e8 90 01 04 47 4b 75 b0 90 00 } //1
		$a_00_2 = {70 7a 6a 67 00 } //2
		$a_00_3 = {06 00 00 00 6d 79 64 6f 77 6e 00 } //2
		$a_00_4 = {06 00 00 00 66 6e 5f 65 78 65 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=7
 
}