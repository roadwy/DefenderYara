
rule VirTool_BAT_Obfuscator_BL{
	meta:
		description = "VirTool:BAT/Obfuscator.BL,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 93 13 07 08 07 93 13 09 11 07 11 04 da 11 09 da 13 0a 06 11 08 11 0a 28 ?? ?? ?? ?? 9d 07 17 d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}