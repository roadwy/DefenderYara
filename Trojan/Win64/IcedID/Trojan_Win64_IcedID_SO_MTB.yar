
rule Trojan_Win64_IcedID_SO_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 eb 90 01 01 8b 4c 24 90 01 01 33 c8 eb 90 01 01 99 f7 7c 24 90 01 01 eb 90 01 01 8b c1 90 00 } //1
		$a_03_1 = {8b 04 24 ff c0 eb 90 01 01 8b c2 48 90 01 01 eb 90 01 01 48 90 01 03 c7 04 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}