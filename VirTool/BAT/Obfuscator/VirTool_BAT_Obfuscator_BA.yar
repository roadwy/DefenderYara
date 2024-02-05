
rule VirTool_BAT_Obfuscator_BA{
	meta:
		description = "VirTool:BAT/Obfuscator.BA,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 1a 58 91 06 28 90 01 03 06 20 ff 00 00 00 5f 28 90 01 04 61 d2 9c 06 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}