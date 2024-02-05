
rule Trojan_Win64_CobaltStrike_BI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 2b 04 24 48 03 44 24 90 01 01 48 03 44 24 90 01 01 0f b6 04 28 30 04 0b ff c3 48 83 ef 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 48 63 d0 48 8d 85 70 ff ff ff 48 89 c1 e8 90 02 04 0f b6 00 30 45 fb 83 45 f4 01 8b 45 f4 48 63 d8 48 8d 85 70 ff ff ff 48 89 c1 e8 90 02 04 48 39 c3 0f 92 c0 84 c0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_BI_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 09 41 30 08 66 89 43 90 01 01 48 8b 43 90 01 01 80 3c 10 90 01 01 48 90 01 04 0f b6 00 88 44 24 90 01 01 0f 85 90 01 04 83 c8 90 01 01 4c 90 01 04 41 88 01 48 90 01 03 80 3c 11 90 01 01 0f 88 90 01 04 48 90 01 04 83 e0 90 01 01 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}