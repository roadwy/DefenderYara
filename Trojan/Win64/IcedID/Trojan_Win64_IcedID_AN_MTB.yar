
rule Trojan_Win64_IcedID_AN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 46 49 75 56 4d 46 61 57 } //01 00 
		$a_01_1 = {46 4b 51 71 4b 6d 51 62 } //01 00 
		$a_01_2 = {48 65 6d 5a 6a 41 59 71 4b 69 } //01 00 
		$a_01_3 = {4a 45 58 59 48 6a 48 65 42 } //01 00 
		$a_01_4 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00 
		$a_01_5 = {53 6c 6d 6c 61 68 77 59 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AN_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {45 52 4a 62 2e 64 6c 6c } //01 00 
		$a_01_1 = {41 56 31 48 45 69 73 61 31 } //01 00 
		$a_01_2 = {47 5a 59 61 71 38 36 56 } //01 00 
		$a_01_3 = {47 68 62 78 35 41 6a } //01 00 
		$a_01_4 = {49 5a 50 44 36 37 5a 39 6d 6a 4f } //01 00 
		$a_01_5 = {64 37 4f 69 65 6d 50 54 41 71 } //01 00 
		$a_01_6 = {64 45 4a 56 78 44 5a 6c 74 4d } //01 00 
		$a_01_7 = {6e 6b 56 56 30 4e 77 76 66 4f } //01 00 
		$a_01_8 = {70 72 61 73 30 77 31 4a 34 52 } //00 00 
	condition:
		any of ($a_*)
 
}