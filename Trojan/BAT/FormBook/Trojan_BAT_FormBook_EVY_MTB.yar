
rule Trojan_BAT_FormBook_EVY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 52 48 41 35 34 34 37 45 38 35 4e 56 34 35 35 51 37 37 4f 54 41 } //01 00 
		$a_01_1 = {4a 00 69 00 6e 00 6a 00 } //01 00 
		$a_01_2 = {43 6f 6e 73 74 72 75 63 74 69 6f 6e 43 61 6c 6c } //01 00 
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}