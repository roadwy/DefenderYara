
rule Trojan_BAT_Formbook_RPP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 5f 03 66 05 5f 60 58 0e 07 0e 04 e0 95 58 7e c7 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 bd 02 00 06 58 54 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}