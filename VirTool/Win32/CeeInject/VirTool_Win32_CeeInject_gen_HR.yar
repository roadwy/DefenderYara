
rule VirTool_Win32_CeeInject_gen_HR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 68 00 30 00 00 8b 45 90 01 01 8b 48 50 51 8b 55 90 01 01 8b 52 34 8b 4d 90 01 01 e8 90 00 } //01 00 
		$a_03_1 = {83 c0 01 a3 90 01 04 8b 4d 90 01 01 0f b7 51 06 39 15 90 01 04 73 90 09 05 00 a1 90 00 } //01 00 
		$a_03_2 = {8b 42 34 8b 4d 90 01 01 03 41 28 89 85 90 00 } //01 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}