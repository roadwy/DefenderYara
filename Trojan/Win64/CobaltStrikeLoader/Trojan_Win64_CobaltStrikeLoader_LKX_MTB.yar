
rule Trojan_Win64_CobaltStrikeLoader_LKX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 28 40 00 00 00 48 ?? ?? ?? ?? 49 0f 45 ff c7 44 24 ?? 00 10 00 00 45 33 c0 49 8b ce ff d7 } //1
		$a_01_1 = {d3 ea 80 e2 3f 80 ca 80 41 88 12 4d 8b 13 49 ff c2 4d 89 13 85 c0 7f dc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}