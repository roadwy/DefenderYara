
rule VirTool_Win32_CeeInject_TR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 fb 8b f9 c1 e7 18 0f b6 92 90 01 04 c1 e2 1b 33 d7 c1 ea 18 88 14 31 41 81 f9 90 01 04 72 90 00 } //1
		$a_03_1 = {f7 e9 8b f9 c1 ff 90 01 01 c1 fa 90 01 01 2b d7 69 d2 90 01 04 f7 da 03 d1 0f b6 14 32 30 13 43 41 90 00 } //1
		$a_03_2 = {f7 ee 8b fe c1 ff 90 01 01 03 d6 c1 fa 90 01 01 2b d7 69 c2 90 01 04 f7 d8 03 c6 0f b6 84 18 90 01 04 30 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_CeeInject_TR_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 72 0c 89 4a 04 c7 42 08 00 10 00 00 c7 02 00 00 00 00 ff d0 } //1
		$a_03_1 = {74 d9 8b 44 24 90 01 01 8b 4c 24 90 01 01 83 f1 90 01 01 8b 54 24 90 01 01 8a 1c 02 89 4c 24 90 01 01 8b 4c 24 90 01 01 88 1c 01 83 c0 01 89 44 24 90 01 01 8b 74 24 90 01 01 39 f0 90 00 } //1
		$a_03_2 = {89 fa f7 f1 8b 4c 24 90 01 01 8b 7c 24 90 01 01 89 7c 24 90 01 01 8b 7c 24 90 01 01 29 cf 8a 1c 15 90 01 04 8b 4c 24 90 01 01 8a 3c 31 28 df 8b 54 24 90 01 01 88 3c 32 01 fe 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}