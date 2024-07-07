
rule VirTool_BAT_Obfuscator_BY{
	meta:
		description = "VirTool:BAT/Obfuscator.BY,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 0c 06 16 07 6f 90 01 04 08 20 ff ff 00 00 5f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}