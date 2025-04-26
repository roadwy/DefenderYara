
rule VirTool_Win32_Obfuscator_AAR{
	meta:
		description = "VirTool:Win32/Obfuscator.AAR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 e8 10 12 72 8e c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 8b 45 10 89 45 f0 66 81 65 fc 6f c9 c6 45 e7 00 83 7d 0c 00 74 06 83 7d 08 00 75 02 } //1
		$a_01_1 = {eb 49 eb 09 8b 45 e7 03 45 ef 89 45 e7 8b 45 e7 3b 45 f7 73 33 81 6d eb 22 5f e4 e8 8b 45 0c } //1
		$a_01_2 = {83 7d 14 00 75 08 83 c8 ff e9 ed 00 00 00 8b 4d 14 8b 01 89 45 f4 81 45 e0 42 c2 1e 87 83 7d 10 00 75 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}