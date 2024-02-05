
rule Trojan_Win64_QakBot_RPE_MTB{
	meta:
		description = "Trojan:Win64/QakBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 4e 6e 4e 4c 73 69 76 58 } //01 00 
		$a_01_1 = {42 4b 6f 30 6b 56 57 63 } //01 00 
		$a_01_2 = {42 54 39 79 52 35 74 61 } //01 00 
		$a_01_3 = {43 63 6d 4c 66 53 5a 6c } //01 00 
		$a_01_4 = {44 53 46 67 69 68 67 59 39 6a 70 } //01 00 
		$a_01_5 = {50 6c 75 67 69 6e 49 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}