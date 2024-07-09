
rule Trojan_Win32_Emotet_SG_{
	meta:
		description = "Trojan:Win32/Emotet.SG!!Emotet.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 33 e2 89 45 ?? 81 45 ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 81 75 ?? ?? ?? ?? ?? 8a 4d ?? 8b 7d ?? 0f b7 06 d3 e7 83 f8 41 72 08 83 f8 5a 77 03 83 c0 20 89 45 ?? 83 c6 02 01 55 ?? 33 c0 01 7d ?? 29 5d ?? 66 39 06 0f 85 ?? ff ff ff 5f 5b 8b 45 ?? 5e 8b e5 5d c3 } //1
		$a_03_1 = {33 c0 8b d6 8d 0c bb 8b f9 2b fb 83 c7 03 c1 ef 02 3b d9 0f 47 f8 85 ff 74 2c 8b 75 ?? 8b 0b 8d 5b 04 33 4d ?? 88 0a 8b c1 c1 e8 08 8d 52 04 c1 e9 10 88 42 ?? 88 4a ?? c1 e9 08 46 88 4a ?? 3b f7 72 da } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}