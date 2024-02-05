
rule Trojan_Win64_CobaltStrike_PH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d 28 48 1a 00 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 14 4c 1a 00 43 33 1c 84 } //01 00 
		$a_01_1 = {43 89 1c 81 48 ff c2 66 0f 1f 44 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_PH_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 90 01 01 48 8b 4c 24 90 01 01 0f b6 04 01 89 44 24 90 01 01 48 63 4c 24 90 01 01 33 d2 48 8b c1 b9 15 00 00 00 48 f7 f1 48 8b c2 8b 4c 24 90 01 01 33 8c 84 90 01 04 8b c1 48 63 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}