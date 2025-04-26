
rule VirTool_Win32_Obfuscator_VF{
	meta:
		description = "VirTool:Win32/Obfuscator.VF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff e5 c3 2a 2e 2a 00 55 8b ec 81 } //1
		$a_01_1 = {f3 a4 5e 56 33 c9 66 8b 4e 06 81 c6 f8 00 00 00 } //1
		$a_01_2 = {8b 46 28 03 45 ec ff d0 68 00 80 00 00 6a 00 ff 75 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}