
rule VirTool_BAT_Obfuscator_BX{
	meta:
		description = "VirTool:BAT/Obfuscator.BX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 07 61 08 11 ?? 91 61 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}