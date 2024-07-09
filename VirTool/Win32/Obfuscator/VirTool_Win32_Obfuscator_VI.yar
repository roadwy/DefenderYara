
rule VirTool_Win32_Obfuscator_VI{
	meta:
		description = "VirTool:Win32/Obfuscator.VI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 50 6a ff 8d 8c 24 ?? ?? ?? ?? 51 6a ff 8d 8c 24 ?? ?? ?? ?? 51 50 8b 44 24 ?? 2b c6 33 c3 6a 07 50 8d 84 24 ?? ?? ?? ?? 50 8b 44 24 ?? 8b 40 ?? ff 30 ff 55 } //1
		$a_01_1 = {8a 00 85 c9 0f 85 09 00 00 00 04 50 34 c0 e9 16 00 00 00 8b 4d c4 80 e9 30 80 f1 30 2a c1 8b 4d c0 80 e9 30 80 f1 30 d2 c8 } //1
		$a_02_2 = {03 c3 8d 14 08 02 cb 8a c1 80 e1 03 24 1f f6 e9 b1 fe 2a c8 00 0a 43 e9 ?? ?? ?? ?? 8b 45 f0 83 e9 80 89 4d 08 3b c8 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}