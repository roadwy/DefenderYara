
rule Trojan_BAT_Formbook_PSWF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PSWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 00 6f 0c 00 00 0a 28 90 01 01 00 00 06 13 09 20 01 00 00 00 7e 5d 00 00 04 7b 63 00 00 04 3a b7 ff ff ff 26 20 01 00 00 00 38 ac ff ff ff 11 00 72 61 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 20 03 00 00 00 38 91 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}