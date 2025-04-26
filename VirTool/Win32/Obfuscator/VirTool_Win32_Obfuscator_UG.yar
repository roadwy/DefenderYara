
rule VirTool_Win32_Obfuscator_UG{
	meta:
		description = "VirTool:Win32/Obfuscator.UG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 f2 6c 80 c2 4d 88 11 } //1
		$a_01_1 = {50 68 c2 24 53 00 05 b6 da ff ff } //1
		$a_01_2 = {8b 4d ec 33 ce 33 c6 8d 84 01 4a 25 00 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_UG_2{
	meta:
		description = "VirTool:Win32/Obfuscator.UG,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_09_0 = {ff 56 04 85 c0 75 57 60 8b 7d ec 57 03 7d e8 b0 68 aa 8b 45 fc ab b0 c3 aa 8b 4d e4 5e 8b 7d e0 f3 a4 61 8b 45 d4 50 8b 07 50 ff 56 08 } //1
		$a_09_1 = {60 8b 4d fc 8b 75 f8 8b 7d f4 ad 89 c2 51 c1 e9 02 ad 31 d0 ab e2 fa 59 83 e1 03 83 f9 00 74 06 ac 32 c2 aa e2 fa 61 } //1
	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1) >=2
 
}