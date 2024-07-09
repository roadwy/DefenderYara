
rule Trojan_Win64_PrivateLoader_NPR_MTB{
	meta:
		description = "Trojan:Win64/PrivateLoader.NPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 e0 48 8b c4 48 eb 2e 36 00 00 0f b7 41 ?? 3d 0b 01 00 00 0f 84 f4 36 00 00 3d ?? ?? ?? ?? 0f 85 e2 36 00 00 33 c0 83 b9 84 00 00 00 0e } //5
		$a_03_1 = {44 8b e3 33 c0 48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 b1 05 00 00 85 c0 74 14 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}