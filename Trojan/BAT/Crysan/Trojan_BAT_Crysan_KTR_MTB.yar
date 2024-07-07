
rule Trojan_BAT_Crysan_KTR_MTB{
	meta:
		description = "Trojan:BAT/Crysan.KTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 24 00 00 01 25 d0 05 00 00 04 28 90 01 03 0a 0a 06 0b 16 8d 28 90 01 03 0c 07 7e 07 00 00 04 25 2d 17 26 7e 06 00 00 04 fe 06 0f 00 00 06 73 1c 00 00 0a 25 80 07 00 00 04 28 90 01 03 2b 28 90 01 03 2b 0c 00 d0 2b 00 00 01 28 90 01 03 0a 28 90 01 03 0a 08 6f 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 0d 09 14 6f 90 01 03 0a 26 2a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}