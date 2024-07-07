
rule Trojan_BAT_Formbook_ASDY_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ASDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 19 07 11 15 17 58 09 5d 91 13 1a 11 18 11 19 11 1a 28 } //2
		$a_01_1 = {06 13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c } //1
		$a_01_2 = {11 15 09 5d 13 16 11 15 11 04 5d 13 17 07 11 16 91 13 18 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}