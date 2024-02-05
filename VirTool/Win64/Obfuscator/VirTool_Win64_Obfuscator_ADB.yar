
rule VirTool_Win64_Obfuscator_ADB{
	meta:
		description = "VirTool:Win64/Obfuscator.ADB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 41 28 ca 23 c1 00 } //01 00 
		$a_01_1 = {b9 9e f9 96 ca e8 } //01 00 
		$a_01_2 = {b9 b9 06 a0 bf e8 } //00 00 
		$a_00_3 = {e7 6c } //00 00 
	condition:
		any of ($a_*)
 
}