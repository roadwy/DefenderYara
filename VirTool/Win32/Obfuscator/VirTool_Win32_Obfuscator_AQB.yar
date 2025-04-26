
rule VirTool_Win32_Obfuscator_AQB{
	meta:
		description = "VirTool:Win32/Obfuscator.AQB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 7e 1b 00 00 33 c8 69 c9 d9 14 00 00 81 f1 54 0a 34 07 89 4d fc a0 ?? ?? ?? ?? 0f b6 c0 99 6a 03 59 f7 f9 0f b6 c8 a0 ?? ?? ?? ?? 0f b6 c0 33 c1 8b 4d fc 8a 89 ?? ?? ?? ?? 0f b6 c9 99 f7 f9 c9 c2 20 00 } //1
		$a_03_1 = {8b 0d 70 c1 40 00 b8 24 77 00 00 33 d2 f7 f1 8b 0d ?? ?? ?? ?? 8d 84 01 15 7a 00 00 c2 18 00 66 a1 ?? ?? ?? ?? b9 bd 29 00 00 66 2b c8 69 c9 17 77 00 00 66 8b c1 c2 14 00 8a 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? d3 e8 8b 0d ?? ?? ?? ?? 2b c1 c1 e8 1b c2 1c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=100
 
}