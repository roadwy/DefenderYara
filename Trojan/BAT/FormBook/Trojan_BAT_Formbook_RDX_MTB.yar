
rule Trojan_BAT_Formbook_RDX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0c 11 0c 61 11 0b 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0d 07 11 0a 11 0d d2 9c 11 0a 17 58 13 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}