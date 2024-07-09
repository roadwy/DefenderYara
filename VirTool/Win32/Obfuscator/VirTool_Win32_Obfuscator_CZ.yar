
rule VirTool_Win32_Obfuscator_CZ{
	meta:
		description = "VirTool:Win32/Obfuscator.CZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 a1 08 00 00 00 2d 00 10 00 00 c7 00 01 00 00 00 64 2b 05 08 00 00 00 05 ?? ?? ?? ?? ff e0 64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 48 30 50 31 d2 } //1
		$a_01_1 = {80 c3 30 38 19 75 05 41 41 42 eb e9 58 8b 00 eb d9 58 8b 40 18 50 eb 0d 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 } //1
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 00 00 00 00 31 d2 31 c0 56 80 3e 00 74 0a a6 74 f8 ae 75 fd 5e 42 eb f0 5e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}