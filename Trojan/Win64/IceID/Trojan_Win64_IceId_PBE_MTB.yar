
rule Trojan_Win64_IceId_PBE_MTB{
	meta:
		description = "Trojan:Win64/IceId.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f0 11 01 83 90 01 04 8b 83 90 01 04 ff c8 03 c8 48 8b 83 90 01 04 31 4b 54 41 8b d0 48 63 8b 90 01 04 c1 ea 10 88 14 01 41 8b d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IceId_PBE_MTB_2{
	meta:
		description = "Trojan:Win64/IceId.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d0 8b c2 03 c8 8b c1 03 05 90 01 04 48 98 48 8d 0d 90 01 04 0f be 04 01 8b 8c 24 90 01 04 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 68 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}