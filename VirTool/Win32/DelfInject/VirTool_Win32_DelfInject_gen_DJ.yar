
rule VirTool_Win32_DelfInject_gen_DJ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 e8 03 00 00 90 09 1d 00 07 00 01 00 8d 85 90 01 02 ff ff 50 8b 45 90 01 01 50 ff 15 90 01 03 00 84 c0 0f 84 90 01 01 01 00 00 90 00 } //01 00 
		$a_03_1 = {8b 40 34 50 8b 45 d4 50 ff 15 90 01 03 00 85 c0 75 90 01 01 b8 f4 01 00 00 e8 90 01 02 ff ff 6a 40 68 00 30 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}