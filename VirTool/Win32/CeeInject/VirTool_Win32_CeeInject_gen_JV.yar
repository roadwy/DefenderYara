
rule VirTool_Win32_CeeInject_gen_JV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff 75 90 01 01 ff 95 90 01 02 ff ff 90 00 } //01 00 
		$a_01_1 = {ff b4 08 08 01 00 00 8b 94 08 0c 01 00 00 8d 84 08 f8 00 00 00 03 d1 } //00 00 
	condition:
		any of ($a_*)
 
}