
rule Trojan_Win64_IcedID_KNW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.KNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 98 48 8b 8c 24 a0 01 00 00 0f b6 04 01 8b 4c 24 48 48 63 c9 48 8b 94 24 c8 01 00 00 48 33 04 ca 8b 8c 24 b0 01 00 00 48 63 c9 48 8b 94 24 e0 00 00 00 0f b7 0c 4a 33 d2 48 f7 f1 48 8b 4c 24 40 0f b7 09 83 c1 05 48 63 c9 48 8b 94 24 e8 00 00 00 89 04 8a e9 ae fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}