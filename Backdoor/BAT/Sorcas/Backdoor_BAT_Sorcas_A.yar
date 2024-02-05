
rule Backdoor_BAT_Sorcas_A{
	meta:
		description = "Backdoor:BAT/Sorcas.A,SIGNATURE_TYPE_PEHSTR,32 00 32 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 6f 72 67 75 2e 65 78 65 } //0a 00 
		$a_01_1 = {73 65 74 5f 41 75 74 6f 4c 6f 67 } //0a 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //0a 00 
		$a_01_3 = {45 6d 70 74 79 57 6f 72 6b 69 6e 67 53 65 74 } //0a 00 
		$a_01_4 = {78 35 30 39 43 68 61 69 6e 5f 30 } //0a 00 
		$a_01_5 = {43 6d 64 53 65 72 76 69 63 65 } //0a 00 
		$a_01_6 = {52 75 6e 43 6d 64 } //00 00 
	condition:
		any of ($a_*)
 
}