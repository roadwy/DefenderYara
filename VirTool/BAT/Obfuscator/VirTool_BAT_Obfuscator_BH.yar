
rule VirTool_BAT_Obfuscator_BH{
	meta:
		description = "VirTool:BAT/Obfuscator.BH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e b7 5d 13 90 01 01 11 90 01 01 11 90 01 01 91 11 90 01 01 11 90 01 01 91 61 13 90 01 01 11 90 01 01 17 d6 13 90 01 01 11 90 01 01 11 90 00 } //01 00 
		$a_03_1 = {8e b7 5d 13 90 01 01 11 90 01 01 13 90 01 01 11 90 01 01 11 90 01 01 91 13 90 01 01 11 90 01 01 11 90 01 01 da 20 00 01 00 00 d6 13 90 01 01 11 90 01 01 20 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}