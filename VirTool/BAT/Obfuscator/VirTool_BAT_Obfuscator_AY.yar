
rule VirTool_BAT_Obfuscator_AY{
	meta:
		description = "VirTool:BAT/Obfuscator.AY,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 00 34 00 ?? ?? 38 00 36 00 ?? ?? 31 00 31 00 33 00 ?? ?? 38 00 31 00 ?? ?? 36 00 35 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}