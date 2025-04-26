
rule VirTool_Win64_Obfuscator_D{
	meta:
		description = "VirTool:Win64/Obfuscator.D,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 68 3a 08 00 00 48 8b f8 ff 15 ?? ?? ?? ?? ba 08 00 00 00 48 8b c8 41 b8 23 03 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 74 30 8b 54 24 68 4c 8d 4c 24 68 48 8d 0d c8 36 00 00 41 b8 40 00 00 00 } //1
		$a_03_1 = {48 8b d8 48 85 c0 75 1d 48 8b 0d aa 3e 00 00 44 8d 48 0b 4c 8d 44 24 20 ba e9 03 00 00 ff 15 ?? ?? ?? ?? eb 14 ff 15 46 16 00 00 4c 8b c3 33 d2 48 8b c8 ff 15 ?? ?? ?? ?? ba 08 00 00 00 41 b8 0f 02 00 00 48 8b cf } //1
		$a_01_2 = {8a 01 04 47 41 88 00 0f b6 01 99 83 e0 01 33 c2 3b c2 75 05 ff c3 48 ff c1 ff c3 49 ff c0 48 ff c1 81 fb d6 08 00 00 72 d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}