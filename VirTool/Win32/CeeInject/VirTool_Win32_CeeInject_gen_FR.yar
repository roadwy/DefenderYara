
rule VirTool_Win32_CeeInject_gen_FR{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 41 28 89 85 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {07 00 01 00 90 09 06 00 c7 85 90 00 } //01 00 
		$a_03_2 = {6a 40 68 00 30 00 00 8b 8d 90 01 02 ff ff 8b 51 50 52 8b 85 90 01 02 ff ff 8b 48 34 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}