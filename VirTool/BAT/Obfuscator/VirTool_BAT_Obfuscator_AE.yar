
rule VirTool_BAT_Obfuscator_AE{
	meta:
		description = "VirTool:BAT/Obfuscator.AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {11 0d 16 11 0d 16 95 11 0e 16 95 61 9e 11 0d 17 11 0d 17 95 11 0e 17 95 5a 9e 11 0d 18 11 0d 18 95 11 0e 18 95 58 9e 11 } //01 00 
		$a_02_1 = {13 0d 1f 10 8d 90 01 01 00 00 01 13 0e 16 13 90 01 01 2b 38 11 0d 11 90 01 01 11 0c 9e 11 0e 11 90 01 01 11 0a 9e 11 0a 18 64 11 0a 1e 62 60 13 09 11 0b 1b 64 11 0b 1f 1f 62 60 13 0a 11 90 00 } //01 00 
		$a_02_2 = {2b 39 11 06 25 4b 11 0d 11 90 01 01 1f 0f 5f 95 61 54 11 0d 11 90 01 01 1f 0f 5f 11 0d 11 90 01 01 1f 0f 5f 95 11 06 25 1a 58 13 06 4b 61 20 84 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}