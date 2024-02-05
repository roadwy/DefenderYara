
rule Trojan_Win64_IcedID_SJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 8c 24 90 01 04 eb 90 01 01 83 84 24 90 01 05 c7 84 24 90 01 08 e9 90 01 04 33 c8 8b c1 eb 90 00 } //01 00 
		$a_03_1 = {ff c0 89 04 24 e9 90 01 04 0f b6 04 01 89 44 24 90 01 01 eb 90 01 01 80 44 24 90 01 02 c6 44 24 90 01 02 e9 90 01 04 80 44 24 90 01 02 c6 44 24 90 01 02 eb 90 01 01 f7 bc 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}