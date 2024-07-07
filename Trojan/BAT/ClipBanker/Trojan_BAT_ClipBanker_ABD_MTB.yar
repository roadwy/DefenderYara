
rule Trojan_BAT_ClipBanker_ABD_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 7e 07 00 00 0a 0a 7e 07 00 00 0a 0b 20 f4 01 00 00 28 08 00 00 0a 00 00 28 09 00 00 0a 16 fe 01 13 05 11 05 90 01 05 00 28 0a 00 00 0a 0b 07 06 28 0b 00 00 0a 16 fe 01 13 05 11 05 3a f4 00 00 00 00 72 90 01 04 73 0c 00 00 0a 07 28 0d 00 00 0a 16 fe 01 13 05 11 05 2d 36 00 7e 01 00 00 04 2d 13 14 fe 06 03 00 00 06 73 0e 00 00 0a 80 01 00 00 04 2b 00 7e 01 00 00 04 90 00 } //1
		$a_01_1 = {13 04 11 04 16 6f 10 00 00 0a 00 11 04 6f 11 00 00 0a 00 00 07 0a 00 00 00 de 05 26 00 00 de 00 00 00 17 13 05 38 b5 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}