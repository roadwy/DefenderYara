
rule VirTool_Win32_Obfuscator_BZV{
	meta:
		description = "VirTool:Win32/Obfuscator.BZV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 45 c2 50 ff 55 de 8d 45 ca 50 ff 55 de 8b 45 c2 8b 5d ca 39 d8 74 e8 } //1
		$a_03_1 = {8b 06 83 c6 04 8b 5d f2 31 d8 89 07 83 c7 04 [0-0a] ff 65 ba } //1
		$a_01_2 = {68 00 10 00 00 ff 75 d6 6a 00 ff 95 00 ff ff ff 89 85 fc fe ff ff 8b 4d d6 8b 75 da 8b bd fc fe ff ff f3 a4 6a 40 68 00 10 00 00 ff 75 d6 6a 00 ff 95 00 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}