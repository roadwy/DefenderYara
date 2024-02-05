
rule VirTool_Win32_DelfInject_gen_CO{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 57 ff 47 ff 4d f8 0f 85 b2 f8 ff ff e9 93 00 00 00 } //01 00 
		$a_01_1 = {6a ff ff d7 50 ff d3 eb 17 } //01 00 
		$a_01_2 = {8d 45 f8 50 6a 00 6a 00 68 78 8a 46 00 6a 00 6a 00 ff d3 e9 93 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}