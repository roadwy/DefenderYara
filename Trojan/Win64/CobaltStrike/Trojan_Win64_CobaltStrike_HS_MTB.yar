
rule Trojan_Win64_CobaltStrike_HS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 c3 4c 8b 2d 90 01 04 31 f6 39 f7 7e 90 01 01 48 89 f0 83 e0 90 01 01 41 8a 04 04 32 44 35 90 01 01 88 04 33 48 ff c6 41 ff d5 41 ff d5 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}