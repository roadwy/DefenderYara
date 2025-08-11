
rule Trojan_Win64_CobaltStrike_CCJX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 0f b6 c8 8b 44 24 ?? d3 e8 8b 4c 24 ?? 33 c8 8b c1 8b 4c 24 ?? 81 e1 ?? ?? ?? ?? 33 c1 25 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}