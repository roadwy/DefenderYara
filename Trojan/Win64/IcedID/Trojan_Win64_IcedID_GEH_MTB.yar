
rule Trojan_Win64_IcedID_GEH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c1 ff c1 99 41 f7 f8 33 d2 41 88 44 b4 04 0f b6 87 90 01 04 66 01 05 90 01 04 48 63 05 90 01 04 49 f7 74 f5 00 25 90 01 04 41 09 03 41 0f b6 41 90 01 01 99 41 f7 fa 66 31 05 90 01 04 0f b7 45 00 0f b6 14 87 3b ca 75 90 00 } //01 00 
		$a_01_1 = {43 70 75 72 74 79 68 76 6c 63 } //00 00  Cpurtyhvlc
	condition:
		any of ($a_*)
 
}