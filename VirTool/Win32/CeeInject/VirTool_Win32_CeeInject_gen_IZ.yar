
rule VirTool_Win32_CeeInject_gen_IZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 17 d3 e0 31 d0 01 e8 0f b6 db 31 d8 88 c3 88 06 42 39 54 24 90 01 01 77 e6 89 e8 31 d2 f7 74 24 90 01 01 32 1c 17 88 1e 45 46 39 6c 24 90 01 01 77 90 00 } //01 00 
		$a_03_1 = {0f b6 04 17 d3 e0 31 d0 03 45 90 01 01 0f b6 db 31 d8 88 c3 88 06 42 39 55 90 00 } //01 00 
		$a_03_2 = {c7 00 07 00 01 00 89 44 24 90 01 01 a1 90 01 04 89 04 24 ff 90 03 02 01 54 24 55 90 00 } //01 00 
		$a_03_3 = {83 c5 28 0f b7 50 06 39 fa 7f 90 01 01 81 ff 0c 06 00 00 75 90 00 } //01 00 
		$a_03_4 = {66 83 78 06 00 0f 84 90 01 01 00 00 00 31 c0 31 ff 89 75 90 01 01 89 de 89 c3 90 90 8b 46 3c 8d 94 06 f8 00 00 00 90 00 } //01 00 
		$a_03_5 = {3c 79 0f 84 90 01 02 ff ff 3c 59 0f 84 90 01 02 ff ff 3c 6e 0f 84 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}