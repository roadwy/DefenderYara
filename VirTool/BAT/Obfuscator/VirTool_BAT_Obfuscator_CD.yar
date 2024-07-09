
rule VirTool_BAT_Obfuscator_CD{
	meta:
		description = "VirTool:BAT/Obfuscator.CD,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 1f 4d 9c 11 ?? 17 1f 5a 9c 11 ?? 18 20 90 90 00 00 00 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}