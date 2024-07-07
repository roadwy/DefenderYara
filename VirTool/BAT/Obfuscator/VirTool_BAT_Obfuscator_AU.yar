
rule VirTool_BAT_Obfuscator_AU{
	meta:
		description = "VirTool:BAT/Obfuscator.AU,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 01 11 03 28 90 01 01 00 00 06 26 90 02 20 11 01 11 03 28 90 01 01 00 00 06 11 00 11 04 11 01 29 01 00 00 11 26 90 00 } //1
		$a_03_1 = {11 02 11 01 11 03 28 90 01 01 00 00 06 26 20 90 02 10 11 00 11 04 11 01 29 01 00 00 11 26 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}