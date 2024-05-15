
rule Trojan_Win64_IcedID_LE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.LE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c1 b9 90 01 04 48 f7 f1 48 8b c2 0f b6 44 04 90 01 01 8b 8c 24 90 01 04 33 c8 8b c1 48 63 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}