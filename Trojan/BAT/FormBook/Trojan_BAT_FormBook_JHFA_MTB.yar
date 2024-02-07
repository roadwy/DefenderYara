
rule Trojan_BAT_FormBook_JHFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.JHFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {18 17 8d 19 00 00 01 25 16 07 a2 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 26 07 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //00 00  Bunifu_TextBox
	condition:
		any of ($a_*)
 
}