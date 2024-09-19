
rule Trojan_BAT_Formbook_RDAT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 5d 13 0e 07 11 0e 91 13 0f 11 0f 11 0a 61 13 10 11 10 11 0d 59 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}