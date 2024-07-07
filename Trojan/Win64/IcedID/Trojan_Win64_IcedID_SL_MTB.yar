
rule Trojan_Win64_IcedID_SL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 7c 24 90 01 01 eb 90 01 01 89 44 24 90 01 01 8b 04 24 eb 90 01 01 48 90 01 03 c7 04 24 90 01 04 eb 90 01 01 eb 90 01 01 8b 4c 24 90 01 01 33 c8 eb 90 01 01 48 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}