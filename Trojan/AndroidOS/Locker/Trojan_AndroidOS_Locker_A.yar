
rule Trojan_AndroidOS_Locker_A{
	meta:
		description = "Trojan:AndroidOS/Locker.A,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {70 72 69 76 65 74 } //02 00 
		$a_00_1 = {69 73 5f 69 6d 75 6e 6e 69 74 79 } //02 00 
		$a_00_2 = {33 39 33 38 33 38 } //02 00 
		$a_00_3 = {6c 6f 63 6b 65 72 5f 69 6d 6d 75 6e 69 74 79 } //01 00 
		$a_00_4 = {66 6f 72 63 65 2d 6c 6f 63 6b 65 64 } //01 00 
		$a_00_5 = {53 74 61 72 74 20 75 6e 62 6c 6f 63 6b 65 64 20 70 72 6f 63 65 73 73 21 } //01 00 
		$a_00_6 = {73 61 76 65 5f 6d 65 73 73 61 67 65 5f 68 69 73 74 6f 72 79 } //00 00 
		$a_00_7 = {be a5 00 00 05 00 05 } //00 05 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Locker_A_2{
	meta:
		description = "Trojan:AndroidOS/Locker.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 6f 6c 69 2f 6c 6f 63 6b 2f 6c 6f 63 6b } //01 00 
		$a_00_1 = {4c 63 6f 6d 2f 6d 6f 6c 69 2f 6c 6f 63 6b 2f 42 6f 6f 74 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //01 00 
		$a_00_2 = {4c 61 6e 64 72 6f 69 64 2f 76 69 65 77 2f 57 69 6e 64 6f 77 4d 61 6e 61 67 65 72 24 4c 61 79 6f 75 74 50 61 72 61 6d 73 } //01 00 
		$a_00_3 = {63 6f 6d 2e 61 69 64 65 2e 72 75 6e 74 69 6d 65 2e 56 49 45 57 5f 4c 4f 47 43 41 54 5f 45 4e 54 52 59 } //01 00 
		$a_00_4 = {61 64 64 56 69 65 77 } //00 00 
	condition:
		any of ($a_*)
 
}