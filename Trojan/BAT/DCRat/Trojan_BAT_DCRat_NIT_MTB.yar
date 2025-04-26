
rule Trojan_BAT_DCRat_NIT_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 7e 55 00 00 0a 72 0f 03 00 70 17 6f ?? 00 00 0a 0a 06 02 16 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 00 00 de 1b } //2
		$a_03_1 = {00 00 72 77 03 00 70 28 ?? 00 00 0a 0b 72 77 03 00 70 28 ?? 00 00 0a 00 de 15 26 00 00 de 00 20 d0 07 00 00 28 ?? 00 00 0a 00 00 17 0c 2b d1 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}