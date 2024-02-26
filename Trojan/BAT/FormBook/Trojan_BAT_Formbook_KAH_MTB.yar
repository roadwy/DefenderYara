
rule Trojan_BAT_Formbook_KAH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 11 90 01 01 20 00 01 00 00 5d d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}