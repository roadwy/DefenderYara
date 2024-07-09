
rule VirTool_BAT_Obfuscator_BH{
	meta:
		description = "VirTool:BAT/Obfuscator.BH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e b7 5d 13 ?? 11 ?? 11 ?? 91 11 ?? 11 ?? 91 61 13 ?? 11 ?? 17 d6 13 ?? 11 ?? 11 } //1
		$a_03_1 = {8e b7 5d 13 ?? 11 ?? 13 ?? 11 ?? 11 ?? 91 13 ?? 11 ?? 11 ?? da 20 00 01 00 00 d6 13 ?? 11 ?? 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}