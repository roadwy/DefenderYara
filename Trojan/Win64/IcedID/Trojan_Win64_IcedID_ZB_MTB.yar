
rule Trojan_Win64_IcedID_ZB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e9 d1 fa 8b c2 c1 e8 90 01 01 03 d0 8d 04 92 3b c8 74 05 01 7d 90 01 01 eb 90 01 01 ff 4d 90 01 01 8b 4d 90 01 01 41 90 01 02 f7 e9 8b c2 c1 e8 90 01 01 03 d0 8d 04 52 3b c8 74 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 4d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}