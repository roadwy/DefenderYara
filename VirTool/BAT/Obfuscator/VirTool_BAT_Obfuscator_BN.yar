
rule VirTool_BAT_Obfuscator_BN{
	meta:
		description = "VirTool:BAT/Obfuscator.BN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 fe 0e 00 00 11 01 13 01 11 02 13 02 11 03 13 03 11 04 13 04 14 0a 2b 00 } //00 00 
	condition:
		any of ($a_*)
 
}