
rule Trojan_Win64_CobaltStrike_MKI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 41 f6 f7 48 83 fa 90 01 01 74 90 01 01 0f b6 c0 6b c0 90 01 01 89 d9 28 c1 30 8c 15 90 01 04 48 ff c2 fe c3 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}