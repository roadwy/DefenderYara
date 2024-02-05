
rule VirTool_Win32_VBInject_gen_FV{
	meta:
		description = "VirTool:Win32/VBInject.gen!FV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 06 ff 75 b4 e8 90 01 04 8b c8 8b d6 e8 90 01 04 c7 85 3c ff ff ff 4e 00 00 00 90 00 } //01 00 
		$a_01_1 = {68 c2 8c 10 c5 } //01 00 
		$a_01_2 = {37 00 37 00 2c 00 39 00 30 00 2c 00 31 00 34 00 34 00 2c 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}