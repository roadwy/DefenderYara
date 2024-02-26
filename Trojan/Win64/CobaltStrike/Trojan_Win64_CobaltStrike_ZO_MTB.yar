
rule Trojan_Win64_CobaltStrike_ZO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {ff c0 89 84 24 90 01 04 8b 44 24 90 01 01 39 84 24 90 01 04 7d 90 01 01 48 63 84 24 90 01 04 48 8b 4c 24 90 01 01 0f b6 04 01 83 f0 90 01 01 48 63 8c 24 90 01 04 48 8b 54 24 90 01 01 88 04 0a eb 90 01 01 c7 84 24 90 01 08 eb 90 01 01 8b 84 24 90 01 04 ff c0 89 84 24 90 01 04 8b 44 24 90 01 01 39 84 24 90 01 04 7d 90 01 01 48 63 84 24 90 01 04 48 8b 4c 24 90 01 01 0f b6 04 01 83 f0 90 01 01 48 63 8c 24 90 01 04 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}