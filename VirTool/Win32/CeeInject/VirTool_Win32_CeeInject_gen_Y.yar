
rule VirTool_Win32_CeeInject_gen_Y{
	meta:
		description = "VirTool:Win32/CeeInject.gen!Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 45 0c ff 45 f8 83 c6 28 39 5d f8 7c c7 } //01 00 
		$a_01_1 = {bb e8 03 00 00 0f b6 04 01 03 c7 f7 f3 8b 5d 08 0f b6 04 1e 2b c2 79 05 05 00 01 00 00 88 04 1e 41 46 83 c7 09 3b 75 10 72 ca } //00 00 
	condition:
		any of ($a_*)
 
}