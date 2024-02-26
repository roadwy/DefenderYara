
rule Trojan_BAT_Formbook_SQ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 09 11 05 5d 13 0a 11 09 17 58 13 0b 08 11 0a 91 13 0c 08 11 0a 11 0c 09 11 09 1f 16 5d 91 61 08 11 0b 11 05 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 09 17 58 13 09 11 09 11 05 11 04 17 58 5a fe 04 13 0d 11 0d 2d b1 } //00 00 
	condition:
		any of ($a_*)
 
}