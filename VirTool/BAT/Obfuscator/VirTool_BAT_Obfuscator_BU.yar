
rule VirTool_BAT_Obfuscator_BU{
	meta:
		description = "VirTool:BAT/Obfuscator.BU,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 08 91 7e ?? 00 00 04 08 7e ?? 00 00 04 8e b7 5d 91 61 9c 08 17 58 } //1
		$a_03_1 = {07 08 07 08 91 7e ?? 00 00 04 08 7e ?? 00 00 04 8e b7 5d 91 61 9c 08 17 58 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}