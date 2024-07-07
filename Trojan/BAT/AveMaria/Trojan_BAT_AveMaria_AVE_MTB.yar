
rule Trojan_BAT_AveMaria_AVE_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.AVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 17 00 00 01 25 16 72 de 68 02 70 a2 25 17 72 e4 68 02 70 a2 14 14 14 28 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {50 00 65 00 72 00 70 00 75 00 73 00 74 00 61 00 6b 00 61 00 61 00 6e 00 } //1 Perpustakaan
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}