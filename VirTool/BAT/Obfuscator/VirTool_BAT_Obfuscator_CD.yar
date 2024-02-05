
rule VirTool_BAT_Obfuscator_CD{
	meta:
		description = "VirTool:BAT/Obfuscator.CD,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 1f 4d 9c 11 90 01 01 17 1f 5a 9c 11 90 01 01 18 20 90 90 00 00 00 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}