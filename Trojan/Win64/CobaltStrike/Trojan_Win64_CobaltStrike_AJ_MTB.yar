
rule Trojan_Win64_CobaltStrike_AJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c2 89 44 24 90 01 01 8b 04 24 48 8b 4c 24 90 01 01 0f b6 04 01 8b 4c 24 90 01 01 48 8b 54 24 90 01 01 0f b6 0c 0a 33 c1 8b 0c 24 48 8b 54 24 90 01 01 88 04 0a 8b 04 24 48 8b 4c 24 90 01 01 0f b6 04 01 03 44 24 90 01 01 8b 0c 24 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AJ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 0f af c0 89 43 90 01 01 48 8b 83 90 01 04 88 14 01 48 63 8b 90 01 04 8d 41 90 01 01 89 83 90 01 04 8b 43 90 01 01 2d 90 01 04 0f af 43 90 01 01 89 43 90 01 01 48 8b 83 90 01 04 44 88 4c 01 90 01 01 b8 90 01 04 2b 83 90 01 04 ff 83 90 01 04 89 83 90 01 04 49 81 fb 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}