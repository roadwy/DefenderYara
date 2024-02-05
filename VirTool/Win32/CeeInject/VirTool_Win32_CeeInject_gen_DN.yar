
rule VirTool_Win32_CeeInject_gen_DN{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ea 01 0f 85 90 01 02 ff ff 0f 11 90 01 01 24 90 00 } //01 00 
		$a_01_1 = {0f b6 4c 8c 14 8b 84 24 18 04 00 00 30 0c 02 } //01 00 
		$a_01_2 = {8b 44 24 18 99 f7 7c 24 10 8b 8c 24 28 02 00 00 8a 04 0a 8b 54 24 18 88 84 14 1c 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}