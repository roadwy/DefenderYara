
rule Trojan_BAT_FormBook_AFI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 13 06 2b 1b 00 11 04 11 06 08 11 06 91 09 11 06 09 8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d8 } //01 00 
		$a_01_1 = {6e 00 65 00 75 00 72 00 6f 00 73 00 69 00 6d 00 } //00 00  neurosim
	condition:
		any of ($a_*)
 
}