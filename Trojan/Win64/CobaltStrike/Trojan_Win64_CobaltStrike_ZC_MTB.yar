
rule Trojan_Win64_CobaltStrike_ZC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 85 db 0f 84 90 01 04 41 50 41 54 49 c7 c4 00 00 00 00 4d 89 e0 41 5c 49 01 c0 41 54 49 c7 c4 00 00 00 00 4d 01 c4 49 01 0c 24 41 5c ff 34 24 41 58 48 81 c4 90 01 04 48 83 c0 90 01 01 83 eb 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_ZC_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 89 8c 24 90 01 04 8a 54 34 90 01 01 0f b6 44 0c 90 01 01 88 44 34 90 01 01 88 54 0c 90 01 01 8b 94 24 90 01 04 8b b4 24 90 01 04 0f b6 4c 14 90 01 01 0f b6 44 34 90 01 01 03 c8 0f b6 c1 8b 4c 24 90 01 01 0f b6 44 04 90 01 01 30 04 19 41 89 4c 24 90 01 01 3b cf 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}