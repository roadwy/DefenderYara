
rule Trojan_Win64_CobaltStrike_JV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 90 01 01 41 8a 14 14 32 54 05 90 01 01 88 14 06 48 ff c0 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_JV_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.JV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 30 01 48 83 c1 90 01 01 48 39 d1 74 90 01 01 49 63 c2 4c 39 c8 75 90 01 01 4c 89 c0 41 ba 90 01 04 0f b6 00 30 01 48 83 c1 90 01 01 48 39 d1 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}