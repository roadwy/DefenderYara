
rule VirTool_Win32_Obfuscator_GO{
	meta:
		description = "VirTool:Win32/Obfuscator.GO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 80 90 00 00 00 } //1
		$a_01_1 = {ff b0 90 00 00 00 } //1
		$a_01_2 = {25 ee ee ee ee } //2
		$a_03_3 = {2e 00 00 c0 90 09 02 00 81 (e8|f8) } //2
		$a_01_4 = {0f 01 e0 41 83 f9 02 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*3) >=5
 
}