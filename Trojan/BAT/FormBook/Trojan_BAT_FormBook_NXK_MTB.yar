
rule Trojan_BAT_FormBook_NXK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {77 61 68 68 68 68 68 68 68 6e 74 20 74 6f 20 64 65 6c 65 74 65 20 69 73 20 6e 6f 74 20 65 78 69 73 74 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_81_2 = {43 3a 5c 73 6f 67 67 73 73 73 73 73 67 67 67 67 67 67 67 6d 65 64 69 72 65 63 74 6f 72 79 } //01 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00 
	condition:
		any of ($a_*)
 
}