
rule Trojan_BAT_njRat_MBFR_MTB{
	meta:
		description = "Trojan:BAT/njRat.MBFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 01 00 0f 00 08 20 00 04 00 00 58 28 90 01 01 00 00 2b 07 02 08 20 00 04 00 00 20 08 03 00 00 20 40 03 00 00 28 de 01 00 06 0d 08 09 58 0c 09 20 00 04 00 00 fe 04 2c cb 90 00 } //1
		$a_01_1 = {33 2d 35 30 30 31 63 39 30 62 37 31 65 37 } //1 3-5001c90b71e7
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}