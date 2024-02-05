
rule Trojan_Win64_IcedID_MAR_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 56 47 74 2e 64 6c 6c } //01 00 
		$a_01_1 = {41 44 6f 44 6f 74 6c 48 53 4a 5a 46 6d 6e 73 } //01 00 
		$a_01_2 = {46 73 48 61 69 4b 7a 76 4d 54 4f 45 4e 56 70 } //01 00 
		$a_01_3 = {48 4f 76 50 7a 6d 65 70 } //01 00 
		$a_01_4 = {51 44 4b 51 46 51 56 7a 79 6f 57 56 4f 4f 54 76 } //01 00 
		$a_01_5 = {62 61 4f 42 4e 4c 59 70 53 72 56 41 76 77 68 } //00 00 
	condition:
		any of ($a_*)
 
}