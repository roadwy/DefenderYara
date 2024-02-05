
rule Trojan_AndroidOS_Stiniter_A{
	meta:
		description = "Trojan:AndroidOS/Stiniter.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 20 4d 79 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 20 6f 6e 52 65 63 65 69 76 65 20 2d 2d 2d } //01 00 
		$a_01_1 = {41 6e 64 6f 69 64 53 65 72 76 69 63 65 2e 6a 61 76 61 } //01 00 
		$a_01_2 = {25 54 68 72 65 61 64 2d 2d 2d 2d 2d 2d 2d 72 75 6e 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 62 72 65 61 6b 2d 2d 2d 2d 2d 2d } //01 00 
		$a_01_3 = {53 74 61 72 74 20 41 6e 64 6f 69 64 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Stiniter_A_2{
	meta:
		description = "Trojan:AndroidOS/Stiniter.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 20 6f 6e 43 72 65 61 74 65 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 53 65 72 76 69 63 65 20 2d 2d 2d } //01 00 
		$a_01_1 = {2d 2d 2d 73 74 61 72 74 20 72 6f 6f 74 53 61 74 61 65 } //01 00 
		$a_01_2 = {2d 2d 2d 20 65 72 72 6f 72 20 2d 2d 2d } //01 00 
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 6b 65 65 70 65 72 } //01 00 
		$a_01_4 = {47 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 2e 6a 61 76 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Stiniter_A_3{
	meta:
		description = "Trojan:AndroidOS/Stiniter.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 2f 4d 6f 62 69 6c 65 49 6e 66 6f 3e } //01 00 
		$a_01_1 = {48 61 73 5f 4b 65 79 5f 52 65 6c 65 61 73 65 64 } //01 00 
		$a_01_2 = {3b 63 68 6d 6f 64 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 61 6e 64 72 6f 69 64 2e 67 64 77 73 6b 6c 7a 7a 2e 63 6f 6d 2f 67 6f 6f 67 6c 65 6d 65 73 73 61 67 65 2e 61 70 6b } //01 00 
		$a_01_3 = {3b 63 68 6d 6f 64 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 61 6e 64 72 6f 69 64 2e 67 64 77 73 6b 6c 7a 7a 2e 63 6f 6d 2f 67 6f 6f 67 6c 65 73 65 72 76 69 63 65 2e 61 70 6b } //01 00 
		$a_01_4 = {2d 2d 2d 66 61 69 6c 20 77 72 69 74 65 64 61 74 61 69 6e 66 6f } //01 00 
		$a_01_5 = {2d 2d 2d 73 74 61 72 74 20 72 6f 6f 74 53 61 74 61 65 } //00 00 
	condition:
		any of ($a_*)
 
}