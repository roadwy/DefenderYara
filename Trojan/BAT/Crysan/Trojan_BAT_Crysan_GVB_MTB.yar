
rule Trojan_BAT_Crysan_GVB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 05 00 00 04 25 39 05 00 00 00 38 17 00 00 00 26 7e 04 00 00 04 fe 06 0f 00 00 06 73 07 00 00 0a 25 80 05 00 00 04 28 01 00 00 2b 13 02 } //1
		$a_01_1 = {0b 07 20 c0 00 00 00 5f 20 c0 00 00 00 40 2d 00 00 00 07 20 c0 00 00 00 61 1e 62 02 28 c1 02 00 06 60 0c 02 7b 14 01 00 04 08 6f 11 01 00 0a 0d 02 7b 14 01 00 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}