
rule VirTool_Win32_CeeInject_gen_IA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 56 50 8b 46 34 8b 8d 90 01 04 6a 40 68 00 30 00 00 52 50 51 ff 95 90 00 } //01 00 
		$a_03_1 = {0f b7 56 06 83 85 90 01 04 28 43 3b da 7c 90 00 } //01 00 
		$a_03_2 = {8b 46 28 03 46 34 8b 95 90 01 04 8d 8d 90 01 04 51 52 89 85 90 00 } //01 00 
		$a_03_3 = {ff ff 02 00 01 00 90 09 04 00 c7 85 90 00 } //01 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}