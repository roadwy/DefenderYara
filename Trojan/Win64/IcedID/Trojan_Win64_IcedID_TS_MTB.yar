
rule Trojan_Win64_IcedID_TS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 48 63 4c 24 90 01 01 eb 90 00 } //01 00 
		$a_00_1 = {0f b6 8c 0c c0 00 00 00 33 c1 e9 } //01 00 
		$a_03_2 = {48 63 4c 24 1c 48 8b 94 24 90 01 04 e9 90 00 } //01 00 
		$a_00_3 = {88 04 0a e9 } //00 00 
	condition:
		any of ($a_*)
 
}