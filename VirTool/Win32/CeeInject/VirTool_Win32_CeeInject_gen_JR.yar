
rule VirTool_Win32_CeeInject_gen_JR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4b 81 cb 00 ff ff ff 43 0f b6 54 9c 90 01 01 30 14 30 40 3b c5 72 90 00 } //01 00 
		$a_03_1 = {33 d2 8b c1 f7 f5 0f b6 14 1a 03 54 8c 90 01 01 03 fa 81 e7 ff 00 00 80 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}