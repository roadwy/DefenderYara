
rule Trojan_Win64_IcedID_MAK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 6a 68 61 73 79 75 69 6a 6b 61 73 } //01 00 
		$a_01_1 = {51 49 55 78 79 6d } //01 00 
		$a_01_2 = {5a 4a 4e 6f 4a 68 48 36 } //01 00 
		$a_01_3 = {67 4e 33 37 38 6d 58 56 55 59 } //01 00 
		$a_01_4 = {73 68 33 33 63 48 78 4a 41 35 73 } //01 00 
		$a_01_5 = {75 77 6e 53 63 62 75 78 53 4f 49 } //00 00 
	condition:
		any of ($a_*)
 
}