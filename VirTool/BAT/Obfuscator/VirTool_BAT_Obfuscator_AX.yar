
rule VirTool_BAT_Obfuscator_AX{
	meta:
		description = "VirTool:BAT/Obfuscator.AX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 18 00 fe 0c 1c 00 fe 0c 1b 00 fe 0c 1a 00 fe 0c 19 00 28 } //1
		$a_01_1 = {fe 0e 0b 00 fe 0c 0f 00 fe 0c 0e 00 fe 0c 0d 00 fe 0c 0c 00 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}