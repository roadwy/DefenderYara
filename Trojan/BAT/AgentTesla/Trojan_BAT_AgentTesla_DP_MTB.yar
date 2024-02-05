
rule Trojan_BAT_AgentTesla_DP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 13 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 65 63 36 62 35 37 39 64 2d 39 38 63 61 2d 34 61 31 63 2d 39 30 62 66 2d 34 36 31 30 32 30 32 33 31 30 31 37 } //14 00 
		$a_81_1 = {24 39 61 32 32 66 64 36 31 2d 63 30 64 32 2d 34 65 39 34 2d 39 35 34 35 2d 31 37 31 37 38 62 33 61 34 33 31 61 } //14 00 
		$a_81_2 = {24 35 35 33 30 64 37 36 32 2d 33 38 30 30 2d 34 32 39 62 2d 39 66 66 30 2d 64 66 65 32 35 35 37 63 31 34 64 30 } //14 00 
		$a_81_3 = {24 65 33 63 32 39 38 39 65 2d 39 34 30 31 2d 34 65 63 35 2d 39 36 38 37 2d 64 38 63 33 36 36 64 37 34 66 62 65 } //14 00 
		$a_81_4 = {24 66 61 66 62 33 30 38 62 2d 32 33 65 63 2d 34 66 33 32 2d 62 37 30 31 2d 30 66 64 66 37 62 32 66 64 63 65 30 } //01 00 
		$a_81_5 = {50 75 6e 69 73 6d 65 6e 74 53 79 73 74 65 6d 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_6 = {52 69 64 67 65 77 61 79 5f 43 6f 76 65 72 5f 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_7 = {42 69 74 43 6f 6e 76 65 72 74 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_8 = {62 65 6c 6f 6e 67 69 61 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_9 = {24 73 61 66 65 70 72 6f 6a 65 63 74 6e 61 6d 65 24 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_10 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_11 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_12 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_13 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00 
		$a_81_14 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_15 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_16 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00 
		$a_81_17 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_18 = {41 63 74 69 76 61 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}