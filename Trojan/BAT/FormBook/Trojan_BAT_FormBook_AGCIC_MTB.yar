
rule Trojan_BAT_FormBook_AGCIC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGCIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 15 08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 58 13 07 90 00 } //01 00 
		$a_01_1 = {4d 61 67 69 63 55 49 } //00 00  MagicUI
	condition:
		any of ($a_*)
 
}