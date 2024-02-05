
rule Trojan_Win64_CobaltStrike_AH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 2b 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 c1 2b 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 c1 2b 05 90 01 04 48 63 d0 48 8b 4c 24 90 01 01 48 8b 44 24 90 01 01 42 0f b6 04 00 88 04 11 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 01 ff 43 90 01 01 8b 83 90 01 04 33 83 90 01 04 35 90 01 04 89 83 90 01 04 8b 83 90 01 04 48 63 4b 90 01 01 2d 90 01 04 31 43 90 01 01 48 8b 43 90 01 01 44 88 04 01 ff 43 90 01 01 8b 43 90 01 01 33 83 90 01 04 2d 90 01 04 31 43 90 01 01 8b 43 90 01 01 2b 83 90 01 04 2d 90 01 04 01 83 90 01 04 49 81 f9 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 10 83 c2 01 48 83 c0 01 0f b6 d2 48 39 c8 75 ef } //01 00 
		$a_01_1 = {58 51 43 40 56 45 52 6b 7a 5e 54 45 58 44 58 51 43 6b 60 5e 59 53 58 40 44 6b 74 42 45 45 52 59 43 61 52 45 44 5e 58 59 6b 65 42 59 37 } //00 00 
	condition:
		any of ($a_*)
 
}