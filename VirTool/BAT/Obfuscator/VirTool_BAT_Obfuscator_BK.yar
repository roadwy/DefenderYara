
rule VirTool_BAT_Obfuscator_BK{
	meta:
		description = "VirTool:BAT/Obfuscator.BK,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 9c 00 11 90 01 01 17 d6 13 90 01 01 11 90 01 01 11 90 01 01 31 90 01 03 2b 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}