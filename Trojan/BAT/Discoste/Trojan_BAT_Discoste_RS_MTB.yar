
rule Trojan_BAT_Discoste_RS_MTB{
	meta:
		description = "Trojan:BAT/Discoste.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 07 18 6f 0f 00 00 0a 0c 06 08 1f 10 28 10 00 00 0a 6f 11 00 00 0a 26 00 07 18 58 0b 07 02 6f 0c 00 00 0a fe 04 13 04 11 04 2d d3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Discoste_RS_MTB_2{
	meta:
		description = "Trojan:BAT/Discoste.RS!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 72 de 00 00 70 28 08 00 00 06 28 0d 00 00 06 2a } //1
		$a_01_1 = {03 73 23 00 00 0a 28 24 00 00 0a 6f 25 00 00 0a 6f 26 00 00 0a 73 27 00 00 0a 0a 06 6f 28 00 00 0a 0b de 0d 06 2c 06 06 6f 19 00 00 0a dc 26 de ce } //1
		$a_01_2 = {02 28 07 00 00 06 0a 28 21 00 00 0a 06 6f 22 00 00 0a 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}