
rule Trojan_Win64_IcedID_EJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c0 0f b6 84 04 } //01 00 
		$a_01_1 = {8b 8c 24 8c 00 00 00 33 c8 3a c0 } //01 00 
		$a_01_2 = {8b c1 48 63 4c 24 3c } //01 00 
		$a_01_3 = {48 8b 54 24 70 88 04 0a } //00 00 
	condition:
		any of ($a_*)
 
}