
rule Trojan_Win64_ProcBurner_RPW_MTB{
	meta:
		description = "Trojan:Win64/ProcBurner.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0f 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 2e 00 5c 00 52 00 74 00 63 00 6f 00 72 00 65 00 36 00 34 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 57 } //01 00 
		$a_01_2 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 57 } //01 00 
		$a_01_3 = {52 74 6c 47 65 74 4e 74 56 65 72 73 69 6f 6e 4e 75 6d 62 65 72 73 } //01 00 
		$a_01_4 = {52 74 6c 41 64 6a 75 73 74 50 72 69 76 69 6c 65 67 65 } //01 00 
		$a_01_5 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //01 00 
		$a_01_6 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00 
		$a_01_7 = {4c 6f 63 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_8 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00 
		$a_01_9 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c } //01 00 
		$a_01_10 = {47 00 65 00 74 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 49 00 6e 00 66 00 6f 00 57 00 } //01 00 
		$a_01_11 = {56 00 65 00 72 00 51 00 75 00 65 00 72 00 79 00 56 00 61 00 6c 00 75 00 65 00 57 00 } //01 00 
		$a_01_12 = {66 00 69 00 6e 00 64 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6f 00 62 00 6a 00 65 00 63 00 74 00 74 00 61 00 62 00 6c 00 65 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 } //01 00 
		$a_01_13 = {66 00 69 00 6e 00 64 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 65 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 } //01 00 
		$a_01_14 = {6c 00 65 00 76 00 65 00 6c 00 20 00 32 00 20 00 68 00 61 00 6e 00 64 00 6c 00 65 00 20 00 74 00 61 00 62 00 6c 00 65 00 20 00 6e 00 6f 00 74 00 20 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}