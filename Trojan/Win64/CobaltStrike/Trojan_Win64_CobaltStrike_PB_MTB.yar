
rule Trojan_Win64_CobaltStrike_PB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa 90 01 01 89 c8 c1 f8 90 01 01 29 c2 89 d0 6b c0 90 01 01 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 1c 05 00 00 90 01 01 8b 85 1c 05 00 00 3b 85 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_PB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d0 f7 d0 25 90 01 04 81 e2 90 01 04 09 c2 81 f2 90 01 04 89 15 90 00 } //01 00 
		$a_03_1 = {0f b6 09 89 ca f6 d2 89 c3 f6 d3 41 89 d0 41 80 e0 90 01 01 80 e1 90 01 01 44 08 c1 08 da 80 e3 90 01 01 24 90 01 01 08 d8 30 c8 f6 d2 08 c2 48 8b 45 90 01 01 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}