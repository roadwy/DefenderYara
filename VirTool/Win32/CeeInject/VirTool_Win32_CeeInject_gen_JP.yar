
rule VirTool_Win32_CeeInject_gen_JP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 46 3c 03 c6 a3 90 01 04 81 38 50 45 00 00 0f 85 90 09 0d 00 4d 5a 00 00 66 39 90 01 01 0f 85 90 00 } //01 00 
		$a_03_1 = {8b 50 50 8b 40 34 8b 0d 90 01 04 6a 40 68 00 30 00 00 52 50 51 ff 90 03 01 02 55 54 24 90 00 } //01 00 
		$a_01_2 = {0f b7 50 06 47 83 c3 28 3b fa 7c } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}