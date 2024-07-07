
rule VirTool_WinNT_Almanahe_gen_A{
	meta:
		description = "VirTool:WinNT/Almanahe.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 75 dc 39 3e 75 54 81 7e 18 73 45 72 76 75 4b c6 45 e7 01 8b f7 89 75 dc 89 5d fc 38 5d e7 74 } //2
		$a_01_1 = {89 7d d0 e9 3d ff ff ff c7 45 d8 25 02 00 c0 eb 07 } //1
		$a_01_2 = {89 7d fc 74 8b eb 19 3b 7d 1c 75 09 c7 45 30 06 00 00 80 eb 0b 6a 00 56 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}