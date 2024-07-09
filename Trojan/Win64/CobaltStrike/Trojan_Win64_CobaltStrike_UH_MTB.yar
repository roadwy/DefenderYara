
rule Trojan_Win64_CobaltStrike_UH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.UH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 04 01 66 89 04 24 8b 44 24 ?? ff c0 89 44 24 ?? 0f b7 04 24 8b 4c 24 ?? c1 e9 ?? 8b 54 24 ?? c1 e2 ?? 0b ca 03 c1 8b 4c 24 ?? 33 c8 8b c1 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}