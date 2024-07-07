
rule VirTool_Win32_Obfuscator_DS{
	meta:
		description = "VirTool:Win32/Obfuscator.DS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 5d 0c 0b 90 03 01 04 0f 90 01 01 0f 84 90 01 02 00 00 90 09 06 00 81 90 04 01 03 e8 2d ff 90 00 } //1
		$a_03_1 = {81 fb 7c 00 00 00 90 03 01 04 74 90 01 01 74 90 09 06 00 81 90 04 01 03 e8 2d ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}