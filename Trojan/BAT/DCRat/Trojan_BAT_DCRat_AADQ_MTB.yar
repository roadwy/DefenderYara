
rule Trojan_BAT_DCRat_AADQ_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 72 0d 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0a dd 90 01 01 00 00 00 26 dd 00 00 00 00 06 2c d1 90 00 } //2
		$a_01_1 = {38 00 30 00 2e 00 36 00 36 00 2e 00 38 00 39 00 2e 00 39 00 33 00 } //1 80.66.89.93
		$a_01_2 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}