
rule Trojan_AndroidOS_Boxer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Boxer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 45 59 5f 4d 45 53 53 41 47 45 5f 44 41 54 41 5f 54 45 58 54 } //01 00 
		$a_01_1 = {67 65 74 50 72 65 66 69 78 41 6e 64 4e 75 6d 62 65 72 } //01 00 
		$a_01_2 = {63 6e 74 72 79 54 61 67 } //01 00 
		$a_01_3 = {4b 45 59 5f 53 55 42 49 44 5f 52 45 43 45 49 56 45 44 } //01 00 
		$a_01_4 = {62 65 67 69 6e 53 65 6e 64 69 6e 67 } //01 00 
		$a_01_5 = {67 65 74 4d 6d 69 52 75 6e 6e 69 6e 67 54 65 78 74 } //00 00 
		$a_00_6 = {5d 04 00 00 } //f6 31 
	condition:
		any of ($a_*)
 
}