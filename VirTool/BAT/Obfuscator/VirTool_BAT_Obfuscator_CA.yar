
rule VirTool_BAT_Obfuscator_CA{
	meta:
		description = "VirTool:BAT/Obfuscator.CA,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 d6 0a 06 17 d6 0a 06 17 d6 0a 11 ?? 11 ?? 11 ?? 11 ?? 91 11 ?? 11 ?? 11 ?? 5d 91 61 9c 06 17 d6 0a 06 17 d6 0a 06 17 d6 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}