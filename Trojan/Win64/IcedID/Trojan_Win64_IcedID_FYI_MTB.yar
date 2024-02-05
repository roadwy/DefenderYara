
rule Trojan_Win64_IcedID_FYI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.FYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {f7 bc 24 18 90 01 03 8b c2 eb 90 01 01 33 c8 8b c1 eb 90 01 01 48 63 0c 24 48 8b 94 24 90 01 04 e9 9b 90 00 } //05 00 
		$a_03_1 = {ff c0 89 04 90 01 01 eb 24 80 44 24 4a 90 01 01 c6 44 24 4b 90 01 01 eb 90 01 01 80 44 24 50 90 01 01 c6 44 24 51 90 01 01 eb 90 01 01 80 44 24 4f 90 01 01 c6 44 24 50 90 01 01 eb 90 00 } //01 00 
		$a_01_2 = {48 62 61 73 68 66 6b 6a 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}