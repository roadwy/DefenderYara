
rule Trojan_Win64_IcedID_YAB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 48 98 90 13 48 8b 90 01 01 24 90 02 04 0f b6 04 01 90 13 8b 4c 24 04 33 c8 90 13 8b c1 48 63 0c 24 90 13 48 8b 90 01 01 24 90 02 04 88 04 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}