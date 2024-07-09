
rule Trojan_BAT_RedLineStealer_NEC_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 03 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? 06 07 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d da } //1
		$a_01_1 = {00 18 0a 04 28 e7 01 00 0a 0b 07 72 a4 0b 00 70 6f e8 01 00 0a 0c 08 2c 06 00 06 17 59 0a 00 03 07 06 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}