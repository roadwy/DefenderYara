
rule Trojan_Win64_CobaltStrike_PQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b cb 44 38 6d ?? 74 ?? 45 85 c9 7e ?? 48 8d 95 ?? ?? ?? ?? 48 2b d3 45 8b c1 8a 04 0a 30 01 48 ff c1 49 83 e8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_PQ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 83 f1 28 0f af c8 41 8b d1 45 8b c1 c1 ea 18 41 c1 e8 10 89 8b [0-04] 48 63 8b [0-04] 8b 83 [0-04] 33 83 [0-04] 83 e8 12 01 43 [0-04] 8b 43 [0-04] 29 83 [0-04] 48 8b 83 [0-04] 88 14 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}