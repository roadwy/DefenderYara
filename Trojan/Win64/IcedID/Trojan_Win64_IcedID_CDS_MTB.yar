
rule Trojan_Win64_IcedID_CDS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.CDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 ff c0 48 90 01 03 10 eb 90 01 01 eb 90 01 01 8a 09 88 08 eb 90 01 01 48 89 44 24 90 01 01 48 8b 44 24 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {33 c8 8b c1 eb 90 01 01 f7 bc 24 90 01 04 8b c2 eb 90 01 01 83 84 24 90 01 05 c7 84 24 90 01 08 eb 90 01 01 48 63 0c 24 48 8b 94 24 90 01 04 e9 90 01 04 83 84 24 90 01 05 c7 84 24 90 01 08 e9 90 00 } //01 00 
		$a_01_2 = {4c 6a 61 73 6b 64 61 73 73 64 } //00 00  Ljaskdassd
	condition:
		any of ($a_*)
 
}