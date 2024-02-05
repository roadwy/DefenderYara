
rule Trojan_Win64_IcedID_EE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 eb c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b c3 ff c3 8d 0c 52 c1 e1 90 01 01 2b c1 48 63 c8 48 8b 44 24 90 01 01 42 0f b6 8c 39 90 01 04 41 32 4c 00 90 01 01 43 88 4c 08 90 01 01 3b 5c 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}