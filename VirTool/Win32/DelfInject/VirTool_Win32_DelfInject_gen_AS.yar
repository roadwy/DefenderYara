
rule VirTool_Win32_DelfInject_gen_AS{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 26 8b 45 e0 8b 40 28 03 45 f0 } //01 00 
		$a_01_1 = {b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 66 ba 58 56 ed } //01 00 
		$a_01_2 = {0f 3f 07 0b 36 } //00 00 
	condition:
		any of ($a_*)
 
}