
rule Trojan_Win64_CobaltStrike_AI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 3c 08 8b 84 24 90 01 04 99 b9 90 01 04 f7 f9 48 63 ca 48 8b 44 24 90 01 01 0f b6 04 08 8b d7 33 d0 48 63 8c 24 90 01 04 48 8b 44 24 90 01 01 88 14 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 39 44 24 90 01 01 44 89 c0 76 90 01 01 99 f7 f9 48 8d 05 90 01 04 48 63 d2 8a 14 10 48 8b 84 24 90 01 04 42 32 14 00 42 88 14 06 49 ff c0 eb 90 00 } //01 00 
		$a_00_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 89 cf 48 8b 58 10 48 89 de 48 8b 4b 60 48 89 fa } //00 00 
	condition:
		any of ($a_*)
 
}