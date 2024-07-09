
rule VirTool_Win32_Obfuscator_AGO{
	meta:
		description = "VirTool:Win32/Obfuscator.AGO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {60 33 db 8d bb 00 b1 6c 00 b9 } //1
		$a_03_1 = {2b db 33 d2 b9 00 00 00 00 60 61 8d bb 00 b1 6b 00 57 be 00 00 00 00 b9 f0 ff 8f 00 bb ?? ?? ?? ?? 03 f3 60 f3 a4 61 } //1
		$a_03_2 = {8a 06 88 07 46 47 49 eb ?? 33 db 8d bb 00 b1 6b 00 b9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_AGO_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AGO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 a5 66 a5 83 c4 04 68 ?? ?? ?? 00 a4 ff 15 ?? ?? ?? 00 0f b7 ?? ?? ?? ?? 00 69 c0 f0 49 02 00 33 c9 85 c0 7e ?? 8b c1 99 be 03 00 00 00 f7 fe 85 d2 74 ?? 8a ?? ?? ?? ?? 00 a1 ?? ?? ?? 00 80 c2 ?? 30 14 08 0f b7 ?? ?? ?? ?? 00 69 c0 f0 49 02 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}