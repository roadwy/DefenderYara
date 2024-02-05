
rule VirTool_BAT_Obfuscator_AO{
	meta:
		description = "VirTool:BAT/Obfuscator.AO,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 72 2e 48 61 63 6b 65 72 73 20 44 5a 20 44 45 56 2d 50 4f 49 4e 54 2e 73 6e 6b } //01 00 
		$a_01_1 = {48 61 6d 7a 61 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {25 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4e 00 61 00 6d 00 65 00 25 00 } //00 00 
	condition:
		any of ($a_*)
 
}