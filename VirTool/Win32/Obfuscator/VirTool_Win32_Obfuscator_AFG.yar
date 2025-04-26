
rule VirTool_Win32_Obfuscator_AFG{
	meta:
		description = "VirTool:Win32/Obfuscator.AFG,SIGNATURE_TYPE_PEHSTR_EXT,08 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 32 db 81 e3 99 f0 ff ff 32 db 89 5d fc 81 c3 00 0e 00 00 83 eb 04 8b 4d 08 89 0b } //2
		$a_01_1 = {68 2d 2d 2d 2d 89 65 dc 8b 45 dc e8 00 00 00 00 59 03 4d b8 83 c1 09 ff e1 50 50 } //2
		$a_01_2 = {c9 83 c4 18 66 3d 34 12 75 19 c1 e8 10 87 04 24 50 68 00 40 00 00 } //1
		$a_01_3 = {eb 19 ff 75 ec ff 75 ec ff 75 ec ff 75 ec ff 55 dc 64 a1 18 00 00 00 3e 8b 40 34 83 e8 06 74 } //1
		$a_01_4 = {80 04 24 f2 8b 04 24 8b 40 01 83 c0 05 01 04 24 58 89 45 f0 8b 04 24 6a 40 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}