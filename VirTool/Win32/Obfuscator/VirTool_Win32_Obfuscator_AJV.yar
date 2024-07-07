
rule VirTool_Win32_Obfuscator_AJV{
	meta:
		description = "VirTool:Win32/Obfuscator.AJV,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 "
		
	strings :
		$a_11_0 = {25 ff 00 00 00 8a 04 10 3c ff 74 22 c1 e3 06 0a d8 58 c1 e8 08 49 75 e7 8b c3 c1 e0 08 86 e0 c1 c8 10 86 e0 ab 4f 59 49 75 ad 01 } //1
		$a_68_2 = {39 3a 3b 68 34 35 36 37 68 30 31 32 33 68 2c 2d 2e 2f 68 28 29 2a 2b 68 24 25 26 27 68 20 21 22 23 68 1c 1d 1e 1f 68 18 19 1a 1b 68 14 15 16 17 68 10 11 12 13 68 0c 0d 0e 0f 68 08 09 0a 0b } //15933
	condition:
		((#a_11_0  & 1)*1+(#a_68_2  & 1)*15933) >=1
 
}