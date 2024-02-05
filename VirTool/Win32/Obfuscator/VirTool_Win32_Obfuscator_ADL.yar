
rule VirTool_Win32_Obfuscator_ADL{
	meta:
		description = "VirTool:Win32/Obfuscator.ADL,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e3 10 b9 ff ff 00 00 53 e8 9a ff ff ff 3d 90 01 04 75 03 89 5d b4 43 e2 ed 61 83 7d b4 00 0f 84 00 01 00 00 90 00 } //01 00 
		$a_01_1 = {8b 45 b4 bb 95 64 19 00 33 d2 81 c3 78 01 00 00 f7 e3 05 5f f3 6e 3c 50 8f 45 b4 ad 33 45 b4 ab e2 de } //01 00 
		$a_01_2 = {b9 fe ff 01 00 03 c3 33 45 08 d1 c0 43 e2 f6 89 44 24 1c } //00 00 
	condition:
		any of ($a_*)
 
}