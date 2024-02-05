
rule VirTool_Win32_CeeInject_gen_CN{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {99 f7 fe 0f b6 82 90 01 04 30 81 90 01 04 8b 54 24 90 01 01 8d 84 90 01 05 99 f7 fe 83 c1 05 0f b6 82 90 01 04 30 81 90 01 04 83 f9 90 00 } //01 00 
		$a_02_1 = {8a 44 b4 10 8b 54 bc 10 89 54 b4 10 0f b6 c0 89 44 bc 10 33 d2 8d 41 ff f7 f3 0f b6 92 90 01 04 03 d7 03 54 b4 14 8b fa 81 e7 ff 00 00 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}