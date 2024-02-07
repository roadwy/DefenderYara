
rule Trojan_BAT_FormBook_Y_MTB{
	meta:
		description = "Trojan:BAT/FormBook.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 05 11 02 6f } //02 00 
		$a_03_1 = {14 14 11 06 74 90 01 01 00 00 1b 6f 90 01 01 00 00 0a 26 90 00 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}