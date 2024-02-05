
rule Trojan_Win64_IcedID_MAO_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 44 77 42 30 30 6f } //01 00 
		$a_01_1 = {58 38 70 37 72 58 65 30 4e 6b } //01 00 
		$a_01_2 = {6b 6d 44 79 4a 77 } //01 00 
		$a_01_3 = {6b 7a 74 37 69 4d 61 5a } //01 00 
		$a_01_4 = {71 39 62 76 62 4b 42 73 } //01 00 
		$a_01_5 = {73 76 79 54 41 37 48 5a } //00 00 
	condition:
		any of ($a_*)
 
}