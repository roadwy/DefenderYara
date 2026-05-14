
rule Trojan_Win64_KazuarLoader_CG_MTB{
	meta:
		description = "Trojan:Win64/KazuarLoader.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 8a 0e 48 8b 1d ?? ?? ?? ?? 83 c9 ?? 88 0b 41 8a 5d 00 0f b6 0c 06 31 d1 80 fb ?? 74 } //5
		$a_03_1 = {8a 04 17 4c 8b 3d ?? ?? ?? ?? 31 c8 88 04 13 41 8a 07 48 ff c2 4c 8b 3d ?? ?? ?? ?? 41 0f af c6 41 88 07 e9 } //5
		$a_03_2 = {45 8a 1f 89 d2 8a 54 14 ?? 45 8d 43 ?? 4c 8b 1d ?? ?? ?? ?? 45 88 03 30 14 03 48 ff c0 e9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}