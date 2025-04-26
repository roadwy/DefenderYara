
rule Trojan_BAT_Formbook_RS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 06 08 8e 69 32 e6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Formbook_RS_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 06 0b 28 3f 00 00 0a } //1
		$a_01_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 42 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Formbook_RS_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 90 00 00 0a 28 8d 00 00 0a 16 16 11 09 11 08 18 28 99 00 00 06 28 8d 00 00 0a 18 28 99 00 00 06 28 91 00 00 0a 8c 59 00 00 01 a2 14 28 92 00 00 0a 1e } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Formbook_RS_MTB_4{
	meta:
		description = "Trojan:BAT/Formbook.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 08 09 28 34 00 00 06 28 32 00 00 06 00 28 31 00 00 06 28 33 00 00 06 28 30 00 00 06 00 17 13 04 00 28 2f 00 00 06 d2 06 28 2d 00 00 06 00 00 00 09 17 58 0d 09 17 fe 04 13 05 11 05 2d c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}