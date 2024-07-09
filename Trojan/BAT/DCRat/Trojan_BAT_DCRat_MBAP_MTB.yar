
rule Trojan_BAT_DCRat_MBAP_MTB{
	meta:
		description = "Trojan:BAT/DCRat.MBAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 07 17 94 17 da 17 d6 8d ?? 00 00 01 a2 25 17 28 ?? 01 00 0a 06 16 1e 6f ?? 01 00 0a 6f ?? 01 00 0a a2 25 } //1
		$a_01_1 = {69 00 2e 00 69 00 62 00 62 00 2e 00 63 00 6f 00 2f 00 33 00 52 00 47 00 4b 00 68 00 37 00 70 00 } //1 i.ibb.co/3RGKh7p
		$a_01_2 = {61 2d 36 39 36 37 38 31 65 34 36 38 34 36 } //1 a-696781e46846
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}