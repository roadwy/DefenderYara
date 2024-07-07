
rule Trojan_Win64_IcedID_LK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 04 33 c8 eb 90 01 01 89 44 24 04 8b 04 24 eb 90 01 01 99 f7 bc 24 90 01 04 eb 90 01 01 8b c2 48 98 eb 90 01 01 48 8b 8c 24 90 01 04 0f b6 04 01 eb 90 01 01 8b c1 48 63 0c 24 eb 90 01 01 48 8b 94 24 90 01 04 88 04 0a eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}