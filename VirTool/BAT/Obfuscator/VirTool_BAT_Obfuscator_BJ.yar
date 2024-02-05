
rule VirTool_BAT_Obfuscator_BJ{
	meta:
		description = "VirTool:BAT/Obfuscator.BJ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 da 91 1f 90 01 01 61 0c 03 8e b7 17 d6 8d 90 01 03 01 90 01 0e 11 90 01 02 11 90 01 02 08 61 06 07 91 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}