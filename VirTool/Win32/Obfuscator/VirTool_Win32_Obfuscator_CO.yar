
rule VirTool_Win32_Obfuscator_CO{
	meta:
		description = "VirTool:Win32/Obfuscator.CO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 16 8b ff 83 fd 04 72 02 33 ed 8a 4c 2c 1c 30 0c 38 40 45 3b c3 72 ec 53 57 e8 } //2
		$a_01_1 = {69 c0 6d 4e c6 41 05 39 30 00 00 } //1
		$a_01_2 = {76 1b 83 f9 04 72 02 33 c9 8b 44 24 08 8a 54 0c 10 03 c6 30 10 41 46 3b 74 24 0c 72 e5 } //2
		$a_01_3 = {69 f6 6d 4e c6 41 81 c6 39 30 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}