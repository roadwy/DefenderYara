
rule Trojan_Win64_IcedID_CC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 89 4c 24 20 4c 89 44 24 18 3a c9 74 00 48 89 54 24 10 48 89 4c 24 08 } //01 00 
		$a_01_1 = {44 89 4c 24 20 4c 89 44 24 18 3a e4 } //00 00 
	condition:
		any of ($a_*)
 
}