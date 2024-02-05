
rule VirTool_BAT_Obfuscator_CA{
	meta:
		description = "VirTool:BAT/Obfuscator.CA,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 17 d6 0a 06 17 d6 0a 06 17 d6 0a 11 90 01 01 11 90 01 01 11 90 01 01 11 90 01 01 91 11 90 01 01 11 90 01 01 11 90 01 01 5d 91 61 9c 06 17 d6 0a 06 17 d6 0a 06 17 d6 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}