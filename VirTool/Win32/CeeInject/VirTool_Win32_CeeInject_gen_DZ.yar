
rule VirTool_Win32_CeeInject_gen_DZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 ff 73 50 ff 73 34 ff 75 e0 ff 90 01 02 57 90 00 } //01 00 
		$a_02_1 = {8b 40 0c 03 43 34 50 ff 90 01 02 ff 90 01 02 0f b7 43 06 ff 90 01 02 83 45 f8 28 39 45 fc 7c c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_gen_DZ_2{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 46 28 03 46 34 } //02 00 
		$a_01_1 = {ff 76 50 ff 76 34 } //01 00 
		$a_03_2 = {07 00 01 00 90 03 07 06 90 09 0b 00 c7 84 24 90 09 0a 00 c7 85 90 00 } //01 00 
		$a_03_3 = {07 00 01 00 90 09 03 00 c7 45 90 00 } //f6 ff 
		$a_01_4 = {56 65 72 79 50 44 46 } //01 00  VeryPDF
	condition:
		any of ($a_*)
 
}