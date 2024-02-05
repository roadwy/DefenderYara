
rule Trojan_Win64_IcedID_ST_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 eb 90 01 01 99 f7 7c 24 90 01 01 eb 90 01 01 48 83 ec 90 01 01 c7 04 24 90 00 } //01 00 
		$a_03_1 = {0f b6 04 01 eb 90 01 01 8b 4c 24 90 01 01 33 c8 eb 90 01 01 8b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}