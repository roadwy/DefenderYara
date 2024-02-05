
rule Trojan_Win32_Imminent_A_{
	meta:
		description = "Trojan:Win32/Imminent.A!!Imminent.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 49 6d 6d 69 6e 65 6e 74 5c 50 61 74 68 2e 64 61 74 } //01 00 
		$a_81_1 = {5c 49 6d 6d 69 6e 65 6e 74 5c 4c 6f 67 73 5c } //01 00 
		$a_81_2 = {5c 49 6d 6d 69 6e 65 6e 74 5c 50 6c 75 67 69 6e 73 5c } //01 00 
		$a_81_3 = {4b 65 79 4d 61 6e 61 67 65 72 20 52 65 61 64 79 } //01 00 
		$a_81_4 = {4d 69 63 72 6f 70 68 6f 6e 65 20 52 65 61 64 79 2e } //01 00 
		$a_81_5 = {4d 69 6e 65 72 20 6b 69 6c 6c 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}