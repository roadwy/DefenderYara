
rule VirTool_Win32_CeeInject_gen_FI{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 2e 68 ff 11 00 00 } //01 00 
		$a_01_1 = {8d 46 fe f7 75 14 0f b6 04 13 03 41 fc 03 f8 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}