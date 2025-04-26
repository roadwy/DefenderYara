
rule VirTool_Win32_Obfuscator_AY{
	meta:
		description = "VirTool:Win32/Obfuscator.AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f8 02 75 06 81 c2 00 02 00 00 51 8b 4f 10 83 f8 02 75 06 81 e9 00 02 00 00 57 bf c8 00 00 00 8b f1 e8 27 00 00 00 8b c8 5f b8 ?? ?? ?? ?? 03 c5 e8 24 00 00 00 59 49 eb b1 59 83 c7 28 49 eb 8a 8b 85 ?? ?? ?? ?? 89 44 24 1c 61 ff e0 56 57 4f f7 d7 23 f7 8b c6 5f 5e c3 60 83 f0 05 40 90 90 48 83 f0 05 8b f0 8b fa 60 e8 0b 00 00 00 61 83 c7 08 83 e9 07 e2 f1 61 c3 57 8b 1f 8b 4f 04 68 b9 79 37 9e 5a 42 8b c2 48 c1 e0 05 bf 20 00 00 00 4a 8b eb c1 e5 04 2b cd 8b 6e 08 33 eb 2b cd 8b eb c1 ed 05 33 e8 2b cd 2b 4e 0c 8b e9 c1 e5 04 2b dd 8b 2e 33 e9 2b dd 8b e9 c1 ed 05 33 e8 2b dd 2b 5e 04 2b c2 4f 75 c8 5f 89 1f 89 4f 04 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}