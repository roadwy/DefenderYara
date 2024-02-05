
rule VirTool_BAT_Injector_O{
	meta:
		description = "VirTool:BAT/Injector.O,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 30 24 63 72 79 70 74 65 72 } //01 00 
		$a_01_1 = {66 6b 6f 66 66 } //01 00 
		$a_01_2 = {5d 00 00 06 20 e8 03 00 00 28 06 00 00 0a de 0c } //01 00 
		$a_01_3 = {07 11 04 11 08 6f 2a 00 00 0a 16 } //01 00 
		$a_01_4 = {10 00 00 0a 07 16 6f 11 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}