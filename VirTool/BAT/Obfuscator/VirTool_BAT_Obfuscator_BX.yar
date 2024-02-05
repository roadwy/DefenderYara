
rule VirTool_BAT_Obfuscator_BX{
	meta:
		description = "VirTool:BAT/Obfuscator.BX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {91 07 61 08 11 90 01 01 91 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}