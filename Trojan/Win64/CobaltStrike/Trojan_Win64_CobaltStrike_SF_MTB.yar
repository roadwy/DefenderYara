
rule Trojan_Win64_CobaltStrike_SF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 90 01 01 39 04 24 73 90 01 01 8b 04 24 0f b6 4c 24 90 01 01 48 90 01 04 0f be 04 02 33 c1 8b 0c 24 48 90 01 04 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}