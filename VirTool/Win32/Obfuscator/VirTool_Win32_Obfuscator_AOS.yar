
rule VirTool_Win32_Obfuscator_AOS{
	meta:
		description = "VirTool:Win32/Obfuscator.AOS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 53 50 8b d8 51 8b 0f 8b 06 33 c1 aa 46 59 4b 74 07 49 75 f0 58 5b 5e c3 5b 2b f3 53 eb f3 } //1
		$a_01_1 = {87 f7 ac 8b c8 87 f7 ac 49 48 3b c8 75 09 40 75 ef 5d 5f 5e c2 08 00 8b c2 eb f6 } //1
		$a_01_2 = {66 ad 66 2b c2 74 04 2b f1 eb f5 0f b7 4e 3a 4e 8b c6 48 89 45 fc 8d 44 01 18 b9 09 01 00 00 57 41 41 66 39 08 0f 85 a1 00 00 00 } //1
		$a_01_3 = {8b 45 f8 ff 45 f8 47 47 40 47 47 8b 4d f4 3b c1 72 c3 8b 45 f8 3b 45 f4 73 24 4e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}