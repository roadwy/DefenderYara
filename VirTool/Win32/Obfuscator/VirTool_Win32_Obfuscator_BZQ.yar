
rule VirTool_Win32_Obfuscator_BZQ{
	meta:
		description = "VirTool:Win32/Obfuscator.BZQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 84 24 b4 00 00 00 8a 04 30 8b 4c 24 24 88 04 31 46 3b 74 24 3c 7c d1 39 } //1
		$a_01_1 = {75 03 8a 4d e8 88 0f 8b cb 0f af 4d f8 33 ff 47 2b f9 0f af f8 56 } //1
		$a_01_2 = {75 0e 8b 45 f8 0f af c7 8d 0c 1b 2b c1 89 45 ec ff 45 f4 8b 45 f4 3b 45 0c 7c 89 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}