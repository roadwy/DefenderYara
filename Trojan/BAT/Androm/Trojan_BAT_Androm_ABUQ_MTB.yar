
rule Trojan_BAT_Androm_ABUQ_MTB{
	meta:
		description = "Trojan:BAT/Androm.ABUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {61 31 36 39 31 38 65 64 2d 66 30 33 63 2d 34 31 64 38 2d 61 63 61 62 2d 36 65 32 36 33 63 62 65 64 37 37 30 } //1 a16918ed-f03c-41d8-acab-6e263cbed770
		$a_01_3 = {70 00 72 00 6f 00 74 00 6f 00 6f 00 6c 00 73 00 63 00 68 00 69 00 6c 00 65 00 2e 00 63 00 6c 00 2f 00 58 00 78 00 71 00 70 00 7a 00 64 00 73 00 2e 00 64 00 61 00 74 00 } //2 protoolschile.cl/Xxqpzds.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}