
rule Trojan_BAT_Formbook_PADT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 91 61 07 08 17 58 11 05 5d 91 59 20 00 01 00 00 58 13 06 07 08 11 06 20 ff 00 00 00 5f } //01 00 
		$a_01_1 = {28 aa 00 00 0a 9c 08 17 58 0c 00 08 07 8e 69 fe 04 13 07 11 07 2d 96 } //00 00 
	condition:
		any of ($a_*)
 
}