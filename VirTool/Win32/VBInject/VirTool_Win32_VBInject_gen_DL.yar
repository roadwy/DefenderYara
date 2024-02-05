
rule VirTool_Win32_VBInject_gen_DL{
	meta:
		description = "VirTool:Win32/VBInject.gen!DL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 85 40 fd ff ff 03 85 34 fd ff ff 90 02 06 89 45 84 90 00 } //01 00 
		$a_03_1 = {66 b9 59 00 e8 90 02 38 66 b9 50 00 90 00 } //01 00 
		$a_03_2 = {66 33 0c 42 e8 90 01 02 ff ff 8a d8 ff 75 90 01 01 8b 45 0c ff 30 e8 90 01 02 ff ff 88 18 8b 45 e0 3b 45 d8 0f 8c 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}