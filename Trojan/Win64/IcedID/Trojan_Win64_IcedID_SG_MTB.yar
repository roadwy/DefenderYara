
rule Trojan_Win64_IcedID_SG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 8c 24 90 01 04 eb 90 01 01 f7 bc 24 90 01 04 8b c2 eb 90 01 01 33 c8 8b c1 eb 90 01 01 83 84 24 90 01 05 c7 84 24 90 01 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}