
rule Trojan_BAT_Bladabindi_BTGF_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.BTGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 02 72 66 64 02 70 72 72 64 02 70 28 1d 00 00 0a 0a 06 6f 1e 00 00 0a 1e 5b 8d 24 00 00 01 0b 16 0d 2b 19 00 07 09 06 09 1e 5a 1e 6f 1f 00 00 0a 18 28 20 00 00 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d d6 } //1
		$a_01_1 = {00 12 00 fe 15 05 00 00 02 12 00 02 28 1a 00 00 0a 7d 06 00 00 04 12 00 06 7b 06 00 00 04 6f 1b 00 00 0a 7d 07 00 00 04 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}