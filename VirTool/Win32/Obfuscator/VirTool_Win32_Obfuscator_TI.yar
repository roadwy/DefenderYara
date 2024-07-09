
rule VirTool_Win32_Obfuscator_TI{
	meta:
		description = "VirTool:Win32/Obfuscator.TI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fb ff ff 07 00 01 00 8b 58 3c 03 d8 ff 55 fc 80 a5 ?? fe ff ff 00 6a 3f 89 45 fc 59 33 c0 } //1
		$a_00_1 = {00 54 43 6e 65 72 76 65 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}