
rule Trojan_BAT_AveMariaRat_MG_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 44 6f 6d 61 69 6e } //1 CreateDomain
		$a_01_1 = {77 00 77 00 72 00 72 00 } //1 wwrr
		$a_01_2 = {73 00 33 00 76 00 4a 00 52 00 4a 00 56 00 62 00 59 00 6d 00 41 00 44 00 59 00 4c 00 65 00 78 00 51 00 76 00 } //1 s3vJRJVbYmADYLexQv
		$a_01_3 = {42 6c 61 63 6b 4d 61 72 6b 65 74 } //1 BlackMarket
		$a_01_4 = {72 65 73 74 61 72 74 } //1 restart
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_7 = {50 61 79 6d 65 6e 74 46 6f 72 6d } //1 PaymentForm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}