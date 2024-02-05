
rule Trojan_BAT_FormBook_AFO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 16 13 0a 2b 11 00 09 11 0a 08 11 0a 94 d2 9c 00 11 0a 17 58 13 0a 11 0a 08 8e 69 fe 04 13 0b 11 0b 2d e2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 16 91 13 05 08 17 8d 90 01 03 01 25 16 11 05 9c 6f 90 01 03 0a 09 18 58 0d 09 07 6f 90 01 03 0a fe 04 13 06 11 06 2d c4 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 48 00 61 00 6e 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 31 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 41 00 72 00 69 00 74 00 68 00 6d 00 65 00 74 00 69 00 63 00 47 00 61 00 6d 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFO_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 19 00 02 06 94 07 fe 02 0c 08 2c 09 00 02 06 94 0b 03 06 54 00 00 06 17 58 0a 06 02 8e 69 fe 04 0d 09 2d } //01 00 
		$a_01_1 = {50 00 61 00 6c 00 65 00 6f 00 6c 00 69 00 74 00 68 00 69 00 63 00 20 00 43 00 6f 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}