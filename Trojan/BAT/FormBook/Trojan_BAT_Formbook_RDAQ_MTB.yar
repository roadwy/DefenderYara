
rule Trojan_BAT_Formbook_RDAQ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 04 00 00 04 06 91 03 06 03 8e 69 5d 91 61 d2 9c 00 06 17 58 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}