
rule Trojan_BAT_Formbook_RDAS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 16 73 6d 00 00 0a 13 04 03 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}