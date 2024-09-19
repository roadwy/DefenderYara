
rule Trojan_BAT_Formbook_RDAR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 91 11 07 61 13 1a 07 09 17 58 08 5d 91 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}