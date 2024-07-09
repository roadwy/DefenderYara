
rule VirTool_Win32_Obfuscator_FR{
	meta:
		description = "VirTool:Win32/Obfuscator.FR,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 fb ff ee ff ee [0-0a] 74 [0-0a] 81 fb ee ff ee ff [0-0a] 74 ?? [0-0a] c3 } //10
		$a_02_1 = {b9 05 00 00 00 [0-0b] f7 f1 } //1
		$a_03_2 = {64 8b 1d 30 00 00 00 [0-0a] 8b 9b 90 90 00 00 00 [0-0a] 8b 1b [0-20] 8b 5b 08 } //3
		$a_01_3 = {66 0f 1f 84 00 } //2
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1+(#a_03_2  & 1)*3+(#a_01_3  & 1)*2) >=13
 
}