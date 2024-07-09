
rule VirTool_BAT_Obfuscator_BZ{
	meta:
		description = "VirTool:BAT/Obfuscator.BZ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 61 28 ?? 00 00 0a 6f ?? 00 00 0a 26 09 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}