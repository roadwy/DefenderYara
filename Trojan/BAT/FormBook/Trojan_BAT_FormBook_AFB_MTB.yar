
rule Trojan_BAT_FormBook_AFB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 13 05 11 05 28 90 01 03 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58 90 00 } //01 00 
		$a_01_1 = {53 00 6b 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFB_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 02 7b 04 00 00 04 6f 90 01 03 0a 00 06 6f 90 01 03 0a 0b 07 03 16 03 8e 69 6f 90 01 03 0a 0c 08 0d de 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}