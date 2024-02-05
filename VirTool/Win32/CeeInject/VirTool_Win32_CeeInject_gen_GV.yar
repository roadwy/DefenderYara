
rule VirTool_Win32_CeeInject_gen_GV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 8b 45 90 01 01 8b 48 50 51 8b 55 90 01 01 8b 42 34 90 00 } //01 00 
		$a_01_1 = {c7 45 fc 07 00 01 00 } //01 00 
		$a_03_2 = {0f b6 02 33 c1 8b 0d 90 01 04 03 4d 90 01 01 88 01 8b 95 90 01 01 ff ff ff 83 c2 01 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}