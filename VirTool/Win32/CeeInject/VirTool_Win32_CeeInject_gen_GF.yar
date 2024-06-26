
rule VirTool_Win32_CeeInject_gen_GF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 00 07 00 01 00 } //01 00 
		$a_01_1 = {03 43 28 89 87 b0 00 00 00 } //01 00 
		$a_01_2 = {8b 87 a4 00 00 00 83 c0 08 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_gen_GF_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 50 6a 01 55 81 c5 90 01 04 c7 40 04 90 01 04 c7 00 01 00 00 00 89 78 08 ff d5 be 10 00 00 00 39 74 24 50 72 0d 8b 44 24 3c 50 e8 90 01 04 83 c4 04 c7 44 24 50 0f 00 00 00 90 00 } //01 00 
		$a_02_1 = {6a 00 8b f8 8b 46 90 01 01 6a 02 ff d0 8b e8 90 02 04 83 fd ff 0f 84 90 01 02 00 00 68 28 01 00 00 8d 4c 24 1c 6a 00 51 e8 90 01 04 8b 46 90 01 01 83 c4 0c 8d 54 24 18 52 55 c7 44 24 20 28 01 00 00 90 00 } //01 00 
		$a_02_2 = {01 00 00 c1 4d 90 01 01 0f 0f be 10 8b 4d 90 01 01 03 ca 40 89 4d 90 01 01 38 18 75 90 01 01 81 f9 90 01 04 74 90 01 01 81 f9 90 01 04 74 90 01 01 81 f9 90 01 04 74 90 01 01 81 f9 90 00 } //01 00 
		$a_02_3 = {83 c4 04 50 6a 01 57 81 c7 90 01 04 c7 40 04 90 01 04 c7 00 01 00 00 00 89 48 08 ff d7 be 10 00 00 00 39 b5 90 01 04 72 90 01 01 8b 95 90 01 04 52 e8 90 01 04 83 c4 04 c7 85 90 01 04 0f 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}