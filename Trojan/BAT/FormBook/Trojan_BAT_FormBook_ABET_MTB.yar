
rule Trojan_BAT_FormBook_ABET_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {03 04 1c d6 5d 8c 90 01 03 01 02 28 90 01 03 06 28 90 01 03 0a 0a 06 14 72 90 01 03 70 16 8d 90 01 03 01 14 14 14 28 90 01 03 0a 74 90 01 03 1b 0b 73 90 01 03 0a 0c 08 07 03 1f 0b da 90 00 } //01 00 
		$a_01_1 = {51 00 51 00 57 00 45 00 53 00 53 00 53 00 53 00 } //01 00 
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 4d 00 65 00 6d 00 62 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}