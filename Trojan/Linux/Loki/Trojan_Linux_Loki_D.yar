
rule Trojan_Linux_Loki_D{
	meta:
		description = "Trojan:Linux/Loki.D,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fb 01 0f 84 ?? ?? 00 00 83 fb 11 74 ?? 44 8b 4c 24 04 41 b8 00 54 00 00 8b 3d 46 25 00 00 31 c9 66 44 89 05 ?? ?? ?? ?? ba 54 00 00 00 49 89 e0 48 8d 35 ?? ?? ?? ?? 44 89 0d ?? ?? ?? ?? 41 b9 10 00 00 00 c6 05 ?? ?? ?? ?? 45 c6 05 ?? ?? ?? ?? 40 88 1d } //1
		$a_03_1 = {be 40 00 00 00 48 8d 3d ?? ?? ?? ?? 66 44 89 25 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 35 00 40 40 88 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9 ?? ?? ff ff } //1
		$a_03_2 = {be 01 f0 ff ff ba 08 00 00 00 48 8d 3d ?? ?? ?? ?? 66 44 89 25 ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? be 40 00 00 00 66 89 15 ?? ?? ?? ?? 40 88 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? e9 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}