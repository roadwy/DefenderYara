
rule Trojan_BAT_Androm_ABRN_MTB{
	meta:
		description = "Trojan:BAT/Androm.ABRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e } //1 ReadAsByteArrayAsyn
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {38 00 35 00 2e 00 33 00 31 00 2e 00 34 00 35 00 2e 00 34 00 32 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4) >=7
 
}