
rule VirTool_Win32_Obfuscator_QT{
	meta:
		description = "VirTool:Win32/Obfuscator.QT,SIGNATURE_TYPE_PEHSTR,32 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f 84 2f 01 00 00 39 5d 5c 0f 84 12 01 00 00 8b cf 8d 45 50 33 d2 c6 45 50 43 c6 45 51 4f c6 45 52 4d c6 45 53 50 } //1
		$a_01_1 = {8b 12 6a 04 ff b0 8c 00 00 00 8b 80 88 00 00 00 03 02 83 c1 1c 50 ff 11 c6 45 04 ab c6 45 05 7a c6 45 06 49 c6 45 07 4d c6 45 08 78 c6 45 09 49 } //1
		$a_01_2 = {c6 01 58 c6 41 01 4f c6 41 02 7a c6 41 03 4f c6 41 04 4d c6 41 05 4f c6 41 06 45 c6 41 07 4f c6 41 08 7e c6 41 09 4f c6 41 0a ec c6 00 78 c6 40 01 4f c6 40 02 7a c6 40 03 4f } //1
		$a_01_3 = {66 89 45 e0 6a 6c 58 66 89 45 e2 66 89 45 e4 33 c0 8d 4d dc 66 89 45 e6 88 45 da 8b 43 40 51 89 7d f8 c6 45 c4 4c c6 45 c5 64 c6 45 c6 72 c6 45 c7 46 c6 45 c8 69 c6 45 c9 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}