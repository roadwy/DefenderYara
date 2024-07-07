
rule VirTool_Win32_Obfuscator_ACL{
	meta:
		description = "VirTool:Win32/Obfuscator.ACL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ad 31 d8 ab e2 fa e9 } //1
		$a_01_1 = {89 e5 53 56 57 8b 7d 08 8b 5f 3c 8b 5c 1f 78 01 fb 8b 4b 18 8b 73 20 01 fe ad 01 f8 56 96 31 c0 99 ac 08 c0 74 } //1
		$a_03_2 = {5e 3b 55 0c 75 1a 8b 43 18 29 c8 8b 53 24 01 fa 0f b7 14 42 8b 43 1c 01 f8 8b 04 90 01 f8 eb 02 e2 90 00 } //1
		$a_01_3 = {50 e8 f7 01 00 00 8d 70 02 56 e8 2c 00 00 00 83 e8 02 0f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}