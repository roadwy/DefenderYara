
rule Trojan_Win64_CobaltStrike_AP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 0f b7 44 4c ?? 49 8b c1 41 23 c2 49 8b d5 49 3b c2 49 0f 43 c2 c0 e0 ?? 0f b6 c8 41 0f b7 c1 48 d3 ea 66 41 2b c3 66 41 23 d2 66 33 d0 66 41 33 d0 66 42 89 54 4c ?? 49 ff c1 49 83 f9 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}