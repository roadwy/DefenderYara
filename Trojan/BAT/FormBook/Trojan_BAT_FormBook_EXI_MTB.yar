
rule Trojan_BAT_FormBook_EXI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_81_0 = {43 41 34 45 55 34 4a 37 54 47 34 59 37 42 35 34 34 48 34 38 37 4f } //0a 00 
		$a_81_1 = {49 4b 4d 4e 4a 55 48 42 56 47 59 54 46 43 58 44 52 45 53 5a 41 57 51 } //01 00 
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_3 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00 
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}