
rule Trojan_BAT_Formbook_KAG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {91 61 06 11 90 01 01 20 00 90 01 02 00 5d 91 20 00 90 01 01 00 00 58 20 00 90 01 01 00 00 5d 59 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}