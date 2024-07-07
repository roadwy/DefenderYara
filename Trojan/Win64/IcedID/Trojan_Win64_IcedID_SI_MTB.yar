
rule Trojan_Win64_IcedID_SI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 eb 90 01 01 48 98 48 90 01 07 eb 90 01 01 83 84 24 90 01 05 c7 84 24 90 01 08 eb 90 01 01 48 90 01 03 48 90 01 07 e9 90 01 04 f7 bc 24 90 01 04 8b c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}