
rule Trojan_BAT_ZarazaStelaer_CTP_MTB{
	meta:
		description = "Trojan:BAT/ZarazaStelaer.CTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 70 00 69 00 2e 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 6f 00 72 00 67 00 2f 00 62 00 6f 00 74 00 00 5d 36 00 30 00 30 00 37 00 34 00 30 00 32 00 37 00 32 00 39 00 3a 00 41 00 41 00 45 00 50 00 62 00 30 00 6b 00 30 00 65 00 63 00 5f 00 45 00 69 00 64 00 32 00 67 00 78 00 7a 00 77 00 65 00 53 00 57 00 75 00 4e 00 6a 00 75 00 2d 00 64 00 57 00 68 00 48 00 69 00 63 00 53 00 30 00 00 2b 2f 00 73 00 65 00 6e 00 64 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 3f 00 63 00 68 00 61 00 74 00 5f 00 69 00 64 00 3d } //01 00 
		$a_01_1 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_2 = {5c 00 41 00 56 00 41 00 53 00 54 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_3 = {4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 74 00 61 00 62 00 6c 00 65 00 } //01 00 
		$a_01_4 = {42 00 72 00 61 00 76 00 65 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 72 00 61 00 76 00 65 00 2d 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_5 = {42 00 6c 00 69 00 73 00 6b 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_6 = {53 00 70 00 75 00 74 00 6e 00 69 00 6b 00 5c 00 53 00 70 00 75 00 74 00 6e 00 69 00 6b 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_7 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 45 00 64 00 67 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_8 = {5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_9 = {5c 00 59 00 61 00 20 00 50 00 61 00 73 00 73 00 6d 00 61 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_10 = {5c 00 59 00 61 00 20 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_11 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 6b 00 65 00 79 00 22 00 3a 00 22 00 28 00 2e 00 2a 00 3f 00 29 00 } //00 00 
	condition:
		any of ($a_*)
 
}