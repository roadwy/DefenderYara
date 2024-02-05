
rule VirTool_Win32_CeeInject_gen_T{
	meta:
		description = "VirTool:Win32/CeeInject.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 53 28 8b 7b 34 03 d7 89 95 90 01 02 ff ff 90 00 } //01 00 
		$a_01_1 = {02 c2 8a 14 31 32 d0 88 14 31 } //01 00 
		$a_01_2 = {8b 03 6a 00 81 c2 00 01 00 00 6a 00 52 50 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}