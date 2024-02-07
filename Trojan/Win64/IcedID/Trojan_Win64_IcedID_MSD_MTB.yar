
rule Trojan_Win64_IcedID_MSD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 8c 24 90 01 04 eb 15 90 00 } //01 00 
		$a_00_1 = {33 c8 8b c1 eb a6 } //01 00 
		$a_03_2 = {48 63 0c 24 48 8b 94 24 90 01 04 e9 90 00 } //01 00 
		$a_00_3 = {88 04 0a e9 } //01 00 
		$a_00_4 = {55 6e 73 61 64 6a 6b 62 61 73 66 } //00 00  Unsadjkbasf
	condition:
		any of ($a_*)
 
}