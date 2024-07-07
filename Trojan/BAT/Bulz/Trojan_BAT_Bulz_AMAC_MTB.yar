
rule Trojan_BAT_Bulz_AMAC_MTB{
	meta:
		description = "Trojan:BAT/Bulz.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 9b 00 00 00 00 73 90 01 04 0d 00 08 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 13 04 00 11 04 09 6f 90 01 01 00 00 0a 00 00 de 10 16 2d 0b 11 04 2c 08 11 04 6f 90 01 01 00 00 0a 00 dc 09 6f 90 01 01 00 00 0a 13 05 de 1f 90 00 } //1
		$a_03_1 = {00 15 2c fc 2b 1c 72 90 01 04 7e 90 01 01 00 00 04 2b 17 2b 1c 2b 1d 74 90 01 01 00 00 1b 2b 19 2b 00 2b 18 2a 28 90 01 01 00 00 06 2b dd 6f 90 01 01 00 00 0a 2b e2 0a 2b e1 06 2b e0 0b 2b e4 07 2b e5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}