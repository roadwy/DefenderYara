
rule Trojan_BAT_Agentesla_PSB_MTB{
	meta:
		description = "Trojan:BAT/Agentesla.PSB!MTB,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 65 00 6e 00 70 00 69 00 63 00 6b 00 } //01 00 
		$a_01_1 = {41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4a 00 4b 00 4c 00 4d 00 4e 00 4f 00 50 00 51 00 52 00 53 00 54 00 55 00 56 00 57 00 58 00 59 00 5a 00 } //01 00 
		$a_01_2 = {57 00 69 00 6e 00 52 00 61 00 72 00 2e 00 43 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //01 00 
		$a_01_3 = {53 00 74 00 61 00 72 00 74 00 47 00 61 00 6d 00 65 00 } //01 00 
		$a_01_4 = {53 00 70 00 65 00 63 00 69 00 61 00 6c 00 20 00 42 00 79 00 74 00 65 00 5b 00 5d 00 } //01 00 
		$a_01_5 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00 
		$a_01_6 = {4e 00 6f 00 6e 00 46 00 69 00 63 00 74 00 69 00 6f 00 6e 00 } //01 00 
		$a_01_7 = {45 00 6e 00 74 00 65 00 72 00 20 00 62 00 6f 00 6f 00 6b 00 20 00 67 00 65 00 6e 00 72 00 65 00 3a 00 } //01 00 
		$a_01_8 = {45 00 6e 00 74 00 65 00 72 00 20 00 62 00 6f 00 6f 00 6b 00 20 00 41 00 75 00 74 00 68 00 6f 00 72 00 3a 00 } //01 00 
		$a_01_9 = {45 00 6e 00 74 00 65 00 72 00 20 00 62 00 6f 00 6f 00 6b 00 20 00 74 00 69 00 74 00 6c 00 65 00 3a 00 } //01 00 
		$a_01_10 = {76 00 65 00 6e 00 70 00 69 00 63 00 6b 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00 
		$a_01_11 = {56 4e 59 43 5a 43 57 53 4a 4b 41 41 33 32 47 4d 5a 46 4e 4c 5a 49 58 5a 46 50 54 43 41 59 47 57 52 4d 4f 52 34 43 47 4a } //01 00 
		$a_01_12 = {76 65 6e 70 69 63 6b 4c 33 4b 47 53 46 4d 53 44 56 53 48 57 4a 4d 4e 4c 5a 47 58 5a 46 49 41 49 5a 49 58 32 } //01 00 
		$a_01_13 = {59 45 58 54 35 4e 53 44 34 41 53 5a 46 4e 49 44 56 43 53 47 54 4a 42 41 4f 44 53 47 48 42 55 46 41 } //00 00 
	condition:
		any of ($a_*)
 
}