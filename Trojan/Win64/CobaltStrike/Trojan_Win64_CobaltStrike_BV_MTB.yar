
rule Trojan_Win64_CobaltStrike_BV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 f7 e2 48 d1 ea 48 89 d0 48 01 c0 48 01 d0 48 29 c1 48 89 ca 0f b6 84 15 90 02 04 44 89 c1 31 c1 48 8b 95 90 02 04 8b 85 90 02 04 48 98 88 0c 02 83 85 90 02 04 01 8b 95 90 02 04 8b 85 90 02 04 39 c2 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BV_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 0f 4c f0 eb 90 01 01 48 63 5c 24 90 01 01 48 63 7c 24 90 01 01 48 69 f7 90 01 04 48 89 f1 48 c1 e9 90 01 01 48 c1 ee 90 01 01 01 ce 6b ce 90 01 01 29 cf 40 80 c7 90 01 01 40 30 7c 1c 90 01 01 8b 5c 24 90 01 01 ff c3 eb 90 01 01 bb 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BV_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 e1 ff 0f 00 00 49 8b c0 48 c1 e8 90 02 04 66 29 04 11 0f b7 0f 48 8b c3 81 e1 ff 0f 00 00 48 c1 e8 90 02 04 66 01 04 11 eb 90 02 04 66 83 f8 02 75 90 02 04 81 e1 ff 0f 00 00 66 44 29 04 11 0f b7 07 25 ff 0f 00 00 66 01 1c 10 48 83 c7 02 85 f6 90 00 } //01 00 
		$a_03_1 = {8b 32 8b 7a 90 01 01 8b 4a 90 01 01 49 03 90 01 01 49 03 90 01 01 41 ff 90 01 01 f3 a4 0f b7 45 90 01 01 48 83 c2 28 44 3b 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}