
rule VirTool_Win32_Obfuscator_JJ{
	meta:
		description = "VirTool:Win32/Obfuscator.JJ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c1 2c 24 10 81 04 24 } //01 00 
		$a_03_1 = {ff ff 8c 0c 24 90 09 03 00 68 90 01 07 90 02 16 c3 90 00 } //01 00 
		$a_03_2 = {ff ff 8c 1c 24 90 09 03 00 68 90 01 07 90 02 16 c3 90 00 } //01 00 
		$a_03_3 = {ff ff 8c 24 24 90 09 03 00 68 90 01 07 90 02 16 c3 90 00 } //01 00 
		$a_03_4 = {ff ff 8c 2c 24 90 09 03 00 68 90 01 07 90 02 16 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}