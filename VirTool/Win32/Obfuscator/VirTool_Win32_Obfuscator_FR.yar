
rule VirTool_Win32_Obfuscator_FR{
	meta:
		description = "VirTool:Win32/Obfuscator.FR,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 fb ff ee ff ee 90 02 0a 74 90 02 0a 81 fb ee ff ee ff 90 02 0a 74 90 01 01 90 02 0a c3 90 00 } //10
		$a_02_1 = {b9 05 00 00 00 90 02 0b f7 f1 90 00 } //1
		$a_03_2 = {64 8b 1d 30 00 00 00 90 02 0a 8b 9b 90 90 00 00 00 90 02 0a 8b 1b 90 02 20 8b 5b 08 90 00 } //3
		$a_01_3 = {66 0f 1f 84 00 } //2
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1+(#a_03_2  & 1)*3+(#a_01_3  & 1)*2) >=13
 
}