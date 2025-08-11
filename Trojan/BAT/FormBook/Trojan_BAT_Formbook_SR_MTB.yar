
rule Trojan_BAT_Formbook_SR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 26 11 0a 11 26 11 10 59 61 13 0a 11 10 19 11 0a 58 1e 63 59 13 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}