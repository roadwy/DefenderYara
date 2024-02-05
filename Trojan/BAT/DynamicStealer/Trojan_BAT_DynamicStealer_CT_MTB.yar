
rule Trojan_BAT_DynamicStealer_CT_MTB{
	meta:
		description = "Trojan:BAT/DynamicStealer.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //01 00 
		$a_01_1 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 } //01 00 
		$a_01_2 = {47 65 74 50 61 73 73 77 6f 72 64 73 } //01 00 
		$a_01_3 = {44 00 4c 00 4c 00 2f 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_4 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_5 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00 20 00 2f 00 74 00 6e 00 } //01 00 
		$a_01_6 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 33 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //01 00 
		$a_01_7 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 42 00 49 00 4f 00 53 00 } //01 00 
		$a_01_8 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 } //01 00 
		$a_01_9 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //01 00 
		$a_01_10 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //01 00 
		$a_01_11 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}