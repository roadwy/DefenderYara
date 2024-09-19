
rule Trojan_BAT_Formbook_RF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 91 08 11 ?? 08 8e 69 5d 91 61 d2 9c 00 11 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}