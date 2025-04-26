
rule Trojan_BAT_FormBook_MBAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 de 59 09 2b cc 07 2b cb 6f ?? 00 00 0a 2b c6 13 04 2b c4 08 2b c3 11 04 2b c1 6f ?? 00 00 0a 2b bc 08 2b bb } //1
		$a_01_1 = {49 00 6c 00 62 00 76 00 6e 00 79 00 66 00 6b 00 78 00 71 00 71 00 68 00 6f 00 78 00 } //1 Ilbvnyfkxqqhox
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}