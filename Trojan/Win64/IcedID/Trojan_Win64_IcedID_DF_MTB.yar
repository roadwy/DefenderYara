
rule Trojan_Win64_IcedID_DF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea 8d 04 0a c1 f8 90 01 01 89 c2 89 c8 c1 f8 90 01 01 29 c2 89 d0 89 c2 8d 04 12 89 c2 89 d0 c1 e0 90 01 01 29 d0 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 90 01 04 01 8b 85 90 01 04 3b 85 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DF_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DF!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 44 8c 20 35 69 45 9a 36 89 44 8c 20 48 ff c1 48 83 f9 04 72 ea } //00 00 
	condition:
		any of ($a_*)
 
}