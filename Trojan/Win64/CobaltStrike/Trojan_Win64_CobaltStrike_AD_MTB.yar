
rule Trojan_Win64_CobaltStrike_AD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 17 00 00 00 c1 e2 05 8b c2 41 83 e8 2c 4c 0f af c0 49 8b c2 49 f7 e0 48 c1 ea 07 48 69 c2 ff 00 00 00 41 8b d4 4c 2b c0 41 0f b6 c0 0f 45 c8 41 88 0c 39 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {42 31 04 09 49 83 c1 90 01 01 8b 83 90 01 04 01 43 90 01 01 8b 93 90 01 04 8b 43 90 01 01 81 c2 90 01 04 03 53 90 01 01 2b 43 90 01 01 33 d0 81 f2 90 01 04 89 53 90 01 01 49 81 f9 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}