
rule Trojan_Win64_IcedID_ADD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 eb 90 01 01 8b 4c 24 90 01 01 33 c8 eb 90 01 01 83 84 24 90 01 05 c7 04 24 90 01 04 e9 90 01 04 e9 90 01 04 48 90 01 07 0f b6 04 01 eb 90 01 01 99 f7 bc 24 90 01 04 eb 90 01 01 83 44 24 90 01 02 c7 84 24 90 01 08 eb 90 01 01 8b c2 48 90 01 01 eb 90 01 01 48 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}