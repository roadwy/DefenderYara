
rule Trojan_Win64_IcedID_EX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 0c 50 33 c1 3a ff } //01 00 
		$a_01_1 = {48 63 44 24 2c 0f b6 44 04 50 } //00 00 
	condition:
		any of ($a_*)
 
}