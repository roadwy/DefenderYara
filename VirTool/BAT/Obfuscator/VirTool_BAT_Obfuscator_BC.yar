
rule VirTool_BAT_Obfuscator_BC{
	meta:
		description = "VirTool:BAT/Obfuscator.BC,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 05 02 11 05 91 06 61 07 09 91 61 b4 9c 09 03 6f 90 01 04 17 da 90 00 } //01 00 
		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 04 9c 09 03 6f 90 01 04 17 59 90 00 } //01 00 
		$a_03_2 = {0b 02 02 8e b7 17 da 91 1f 90 01 01 61 0a 02 8e b7 17 d6 90 00 } //01 00 
		$a_03_3 = {0a 02 02 8e 69 17 59 91 1f 90 01 01 61 28 90 01 04 0b 02 8e 69 17 58 90 00 } //01 00 
		$a_01_4 = {0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58 } //00 00 
	condition:
		any of ($a_*)
 
}