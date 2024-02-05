
rule Trojan_Win64_IcedID_CTC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.CTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d0 01 c0 89 c2 c1 e2 04 29 c2 89 c8 29 d0 48 63 d0 48 8b 45 90 01 01 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 45 fc 90 01 01 8b 45 fc 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}