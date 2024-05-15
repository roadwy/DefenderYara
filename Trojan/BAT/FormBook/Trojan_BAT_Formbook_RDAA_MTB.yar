
rule Trojan_BAT_Formbook_RDAA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 0b 11 08 11 0b 61 11 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c 07 09 11 0c } //00 00 
	condition:
		any of ($a_*)
 
}