
rule Trojan_Win64_IcedID_TA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c1 48 63 4c 24 90 01 01 66 3b ff 90 00 } //01 00 
		$a_03_1 = {0f b6 84 04 90 01 04 8b 4c 24 90 01 01 e9 90 01 04 ff c0 99 66 3b f6 74 90 00 } //01 00 
		$a_03_2 = {8b c2 89 44 24 90 01 01 3a f6 74 90 01 01 f7 7c 24 90 01 01 8b c2 3a c9 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}