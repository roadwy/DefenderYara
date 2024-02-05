
rule VirTool_Win32_CeeInject_gen_HG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f bf 5d 06 4b 3b 9c 24 90 01 04 0f 8c 90 01 04 68 28 00 00 00 8b 9c 24 90 01 04 8d 6c 24 90 01 01 8b 7d 3c 8b b4 24 90 01 04 6b f6 28 01 f7 81 c7 f8 00 00 00 90 00 } //02 00 
		$a_03_1 = {8b 5d 34 03 5d 28 53 8d ac 24 90 01 04 58 89 85 b0 00 00 00 90 00 } //01 00 
		$a_01_2 = {89 e8 01 f0 89 c5 8a 26 8a 07 88 c3 88 e7 30 df 88 3e 41 46 47 39 ee 7d 0c } //01 00 
		$a_00_3 = {00 36 35 35 34 33 00 } //00 00 
	condition:
		any of ($a_*)
 
}