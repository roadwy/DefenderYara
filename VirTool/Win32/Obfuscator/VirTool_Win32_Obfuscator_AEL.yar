
rule VirTool_Win32_Obfuscator_AEL{
	meta:
		description = "VirTool:Win32/Obfuscator.AEL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a c1 02 c0 32 c2 32 04 3e 3c 22 90 13 88 04 3e 83 f9 04 90 13 41 46 3b b5 } //1
		$a_03_1 = {8a c1 02 c0 32 04 3e 32 c2 3c 22 90 13 88 04 3e 83 f9 04 90 13 41 46 3b 75 } //1
		$a_01_2 = {53 8a d8 02 db 8d 14 08 32 d3 30 14 3e 83 f8 05 7e 07 b8 02 00 00 00 eb 01 40 46 3b f5 7c e2 5b } //1
		$a_03_3 = {74 29 8b 45 ?? 0f be 88 ?? ?? ?? ?? 8b 55 ?? 83 c2 01 83 f2 ?? 2b ca 8b 45 ?? 88 88 ?? ?? ?? ?? 8b 4d ?? 83 c1 01 89 4d ?? eb ce } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}