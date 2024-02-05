
rule Trojan_AndroidOS_Godfather_A{
	meta:
		description = "Trojan:AndroidOS/Godfather.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 32 31 77 4e 46 39 79 5a 57 4e 76 63 6d 52 6c 63 69 35 77 61 48 41 } //01 00 
		$a_01_1 = {73 65 6e 64 5f 61 6c 6c 5f 70 65 72 6d 69 73 73 69 6f 6e } //01 00 
		$a_01_2 = {73 65 74 74 69 6e 67 5f 61 70 70 5f 6e 6f 74 69 66 69 5f 6c 69 73 74 } //01 00 
		$a_01_3 = {49 6e 76 61 6c 69 64 20 4f 50 45 4e 53 53 48 20 66 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}