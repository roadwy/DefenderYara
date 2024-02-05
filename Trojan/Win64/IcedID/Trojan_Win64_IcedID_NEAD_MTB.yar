
rule Trojan_Win64_IcedID_NEAD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 70 75 72 74 79 68 76 6c 63 } //05 00 
		$a_01_1 = {50 75 44 5a 70 76 76 } //05 00 
		$a_01_2 = {57 46 49 69 75 6c 54 32 32 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}