
rule Trojan_Linux_Loki_C{
	meta:
		description = "Trojan:Linux/Loki.C,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 8b 05 ee 42 00 00 41 83 f8 01 0f 84 ?? ?? 00 00 41 83 f8 11 0f 84 ?? ?? 00 00 8b 4c 24 04 b8 00 54 00 00 [0-05] 44 88 05 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 45 89 0d ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 40 } //1
		$a_03_1 = {41 ba 00 35 00 00 bd 00 40 00 00 44 0f b7 1d ?? ?? ?? ?? be 40 00 00 00 48 8d 3d ?? ?? ?? ?? 66 44 89 15 ?? ?? ?? ?? 66 44 89 1d ?? ?? ?? ?? 66 89 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9 } //1
		$a_03_2 = {be 01 f0 ff ff 31 d2 48 8d 3d ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? be 40 00 00 00 66 89 15 ?? ?? ?? ?? 66 89 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}