
rule Trojan_Win64_IcedID_MAG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 58 4e 61 4b 6b 52 } //01 00 
		$a_01_1 = {4d 74 46 55 69 46 39 54 71 66 4f } //01 00 
		$a_01_2 = {4f 6e 6d 47 43 62 7a } //01 00 
		$a_01_3 = {57 77 37 4a 4d 64 43 5a 6c 53 } //01 00 
		$a_01_4 = {68 4b 67 4a 4d 55 33 61 46 30 63 } //01 00 
		$a_01_5 = {47 59 75 73 64 6b 6e 73 61 } //01 00 
		$a_01_6 = {51 31 65 36 6c 55 77 45 } //01 00 
		$a_01_7 = {63 69 62 4f 62 48 45 6d } //00 00 
	condition:
		any of ($a_*)
 
}