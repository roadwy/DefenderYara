
rule Trojan_BAT_Formbook_RDAF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 1f 16 5d 91 13 06 07 09 07 09 91 11 06 61 11 05 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 09 17 58 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}