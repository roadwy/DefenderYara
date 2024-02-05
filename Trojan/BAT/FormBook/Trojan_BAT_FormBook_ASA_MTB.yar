
rule Trojan_BAT_FormBook_ASA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 26 00 08 11 04 18 6f 90 01 03 0a 20 03 02 00 00 28 90 01 03 0a 13 06 09 11 06 6f 90 01 03 0a 00 11 04 18 58 13 04 00 11 04 08 6f 90 01 03 0a fe 04 13 07 11 07 2d ca 90 00 } //01 00 
		$a_01_1 = {4c 00 54 00 54 00 51 00 5f 00 53 00 55 00 44 00 4f 00 4b 00 55 00 5f 00 47 00 41 00 4d 00 45 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_ASA_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {7b 09 00 00 04 72 59 02 00 70 6f 90 01 03 0a 38 9a f8 ff ff 00 02 16 28 90 01 03 0a 38 62 05 00 00 00 02 7b 0b 00 00 04 6f 90 01 03 0a 38 d7 fa ff ff 00 02 7b 12 00 00 04 6f 90 01 03 0a 38 2a f4 ff ff 00 28 90 00 } //01 00 
		$a_01_1 = {61 00 44 00 61 00 79 00 41 00 74 00 54 00 68 00 65 00 52 00 61 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}