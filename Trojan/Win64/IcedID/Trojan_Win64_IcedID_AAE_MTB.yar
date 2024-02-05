
rule Trojan_Win64_IcedID_AAE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 3b e4 74 90 01 01 b9 90 01 04 48 90 01 02 e9 90 01 04 48 90 01 02 48 90 01 07 66 90 01 02 74 90 01 01 b9 90 01 04 f3 90 01 01 e9 90 01 04 48 90 01 04 0f b6 84 04 90 01 04 3a f6 74 90 01 01 ff c0 89 44 24 90 01 01 e9 90 01 04 8b 00 89 84 24 90 01 04 e9 90 01 04 8b 4c 24 90 01 01 33 c8 3a c9 74 90 01 01 8b d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}