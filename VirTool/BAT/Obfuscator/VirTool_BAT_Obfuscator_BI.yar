
rule VirTool_BAT_Obfuscator_BI{
	meta:
		description = "VirTool:BAT/Obfuscator.BI,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f d8 06 1e 63 d6 0a 08 1d d6 07 20 ff 00 00 00 5f d8 07 1e 63 d6 0b 06 1e 62 07 d6 20 ff 00 00 00 5f 0c 11 04 11 06 02 11 06 91 08 b4 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}