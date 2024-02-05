
rule Trojan_BAT_Bladabindi_BF_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {67 6f 6f 64 2e 64 6c 6c } //01 00 
		$a_81_1 = {47 57 6c 36 76 69 59 64 58 4d 32 36 6a 78 39 49 6c 31 } //01 00 
		$a_81_2 = {45 38 34 46 78 4c 4d 73 46 4a 57 55 57 67 39 75 38 79 } //01 00 
		$a_81_3 = {4a 6c 34 55 54 68 34 78 41 59 59 79 52 72 6f 6a 33 51 } //01 00 
		$a_81_4 = {4a 59 4f 42 49 44 36 50 39 77 6d 79 56 33 4f 32 74 4a } //01 00 
		$a_81_5 = {78 4a 57 42 55 57 67 39 75 } //01 00 
		$a_81_6 = {51 6c 51 64 77 43 48 36 79 } //00 00 
	condition:
		any of ($a_*)
 
}