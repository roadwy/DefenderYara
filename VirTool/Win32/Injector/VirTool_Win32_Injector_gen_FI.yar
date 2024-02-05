
rule VirTool_Win32_Injector_gen_FI{
	meta:
		description = "VirTool:Win32/Injector.gen!FI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d0 83 ec 08 c7 84 24 90 01 04 00 30 00 00 90 02 30 8b 76 34 90 02 30 8b 7f 50 8b 9c 24 90 1b 00 89 44 24 90 01 01 89 e0 89 58 0c 89 78 08 89 70 04 89 10 c7 40 10 40 00 00 00 ff d1 90 00 } //01 00 
		$a_03_1 = {ff d0 83 ec 14 8b 8c 24 d4 01 00 00 8b 94 24 90 01 04 03 4a 28 8b 94 24 dc 01 00 00 89 8a b0 00 00 00 90 00 } //01 00 
		$a_01_2 = {c7 00 07 00 01 00 } //01 00 
		$a_03_3 = {0f b7 49 06 39 c8 0f 8d 35 01 00 00 8b 84 24 90 01 04 8b 40 3c 03 84 24 90 01 04 8b 8c 24 90 01 04 0f af 8c 24 90 01 04 01 c8 89 84 24 f8 00 00 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}