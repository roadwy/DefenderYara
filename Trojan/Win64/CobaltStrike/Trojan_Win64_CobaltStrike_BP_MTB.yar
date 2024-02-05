
rule Trojan_Win64_CobaltStrike_BP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 f8 80 3c 06 90 01 01 74 90 01 01 0f b7 04 06 89 da 48 89 e9 ff c7 c1 ca 90 01 01 01 d0 31 c3 e8 90 01 04 eb 90 00 } //01 00 
		$a_03_1 = {48 89 c2 48 8b 4c 24 90 01 01 83 e2 90 01 01 41 8a 54 15 90 01 01 32 14 07 88 14 01 48 ff c0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {44 8a 0c 10 45 88 c8 41 f6 d0 44 88 84 24 90 02 04 41 80 e0 90 01 01 44 88 84 24 90 02 04 41 80 e1 90 01 01 45 08 c8 44 88 84 24 90 02 04 41 80 f0 90 01 01 44 88 04 10 89 c8 83 c0 01 89 84 24 90 02 04 83 e9 90 01 01 89 8c 24 90 02 04 0f 92 c1 89 84 24 90 02 04 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}