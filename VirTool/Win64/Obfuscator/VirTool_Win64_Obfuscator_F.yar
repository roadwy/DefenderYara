
rule VirTool_Win64_Obfuscator_F{
	meta:
		description = "VirTool:Win64/Obfuscator.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c1 48 8b 4c 24 90 01 01 89 01 90 00 } //01 00 
		$a_03_1 = {91 5f 59 c3 90 09 03 00 eb 01 90 00 } //01 00 
		$a_01_2 = {b9 1c 00 00 00 fc f3 48 a5 ff e0 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}