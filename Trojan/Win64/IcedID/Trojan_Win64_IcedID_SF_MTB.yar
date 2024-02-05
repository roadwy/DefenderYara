
rule Trojan_Win64_IcedID_SF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 0c 24 48 90 01 07 eb 10 0f b6 04 01 8b 4c 24 90 01 01 eb 90 01 01 33 c8 8b c1 eb 90 01 01 88 04 0a e9 90 01 04 48 90 01 06 eb 90 01 01 8b 84 24 90 01 04 39 04 24 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}