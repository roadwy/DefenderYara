
rule Trojan_BAT_FormBook_AFM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 1d 07 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 09 18 58 0d 09 07 6f 90 01 03 0a fe 04 13 06 11 06 2d d4 90 00 } //01 00 
		$a_01_1 = {51 75 61 6e 4c 79 42 61 6e 48 61 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFM_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 d2 06 28 90 01 03 06 00 00 09 1b 59 1c 58 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_01_2 = {43 00 44 00 6f 00 77 00 6e 00 } //01 00 
		$a_01_3 = {52 65 73 75 6d 65 50 6f 72 74 72 61 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}