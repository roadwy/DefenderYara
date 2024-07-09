
rule Trojan_BAT_Bladabindi_AAHC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AAHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 06 28 ?? 00 00 0a 0b 02 13 04 11 04 0c 07 28 ?? 00 00 0a 0d 00 09 6f ?? 00 00 0a 14 17 8d ?? 00 00 01 25 16 08 a2 6f ?? 00 00 0a 26 00 de 37 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}