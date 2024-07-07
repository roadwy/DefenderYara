
rule Trojan_BAT_Formbook_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 07 7e 90 01 01 00 00 04 20 01 00 00 00 97 29 90 01 01 00 00 11 6f 90 01 01 00 00 0a 16 8c 90 01 01 00 00 01 14 6f 90 01 01 00 00 0a 26 2a 90 00 } //5
		$a_01_1 = {4d 30 72 34 70 35 6d 78 5a 30 72 34 70 35 6d 78 } //2 M0r4p5mxZ0r4p5mx
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}