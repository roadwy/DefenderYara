
rule Trojan_BAT_Formbook_AMAD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d [0-0f] 08 58 08 5d 91 [0-28] 5a 58 08 5d 13 [0-14] 61 [0-0f] 59 20 00 02 00 00 58 13 [0-1e] 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}