
rule VirTool_Win32_CeeInject_gen_CW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 b9 00 30 00 00 8b 77 3c 83 ec 08 01 f7 8b 47 54 89 4c 24 0c 89 5c 24 10 a3 90 01 04 8b 47 50 89 44 24 08 8b 47 34 89 44 24 04 a1 90 01 04 89 04 24 ff 15 90 00 } //01 00 
		$a_03_1 = {0f b7 47 14 83 ec 14 8d 74 38 18 31 c0 66 83 7f 06 00 a3 90 01 04 75 90 00 } //01 00 
		$a_03_2 = {8b 5f 28 b9 90 01 04 a1 90 01 04 83 ec 14 01 d8 a3 90 01 04 a1 90 01 04 89 4c 24 04 89 04 24 ff 15 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}