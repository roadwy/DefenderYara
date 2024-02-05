
rule Trojan_Win64_IcedID_MAL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 35 34 49 70 77 50 45 } //01 00 
		$a_01_1 = {41 48 34 6a 61 50 51 4c 32 43 7a } //01 00 
		$a_01_2 = {42 74 4b 47 59 6b 6f 59 78 } //01 00 
		$a_01_3 = {43 75 78 6f 46 4c 79 50 39 } //01 00 
		$a_01_4 = {44 35 5a 63 4d 50 42 34 6d } //01 00 
		$a_01_5 = {46 67 48 4d 4f 74 43 72 5a 49 } //00 00 
	condition:
		any of ($a_*)
 
}