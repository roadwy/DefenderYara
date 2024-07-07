
rule VirTool_Win32_Obfuscator_ACE{
	meta:
		description = "VirTool:Win32/Obfuscator.ACE,SIGNATURE_TYPE_PEHSTR_EXT,14 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8d 70 02 56 8d b5 c9 00 00 00 89 f7 b9 53 00 00 00 ad 35 } //1
		$a_03_1 = {8d b5 16 02 00 00 8d 1c 03 89 f7 b9 90 01 04 ad 31 d8 ab e2 fa e9 90 00 } //1
		$a_01_2 = {60 83 ec 6e fc 89 e7 56 e8 3b } //1
		$a_01_3 = {74 05 3c 9a 75 05 46 8d 74 1e 03 3c c8 74 06 24 f7 3c c2 75 02 46 } //1
		$a_01_4 = {8d 73 0d 6a 64 59 0f a3 0b d6 73 01 ac aa e2 f6 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}