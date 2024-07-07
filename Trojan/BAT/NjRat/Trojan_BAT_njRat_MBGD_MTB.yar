
rule Trojan_BAT_njRat_MBGD_MTB{
	meta:
		description = "Trojan:BAT/njRat.MBGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 3c 02 07 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 03 07 03 6f 90 01 01 00 00 0a 5d 17 d6 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a da 13 04 09 11 04 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0d 07 17 d6 0b 00 07 08 fe 02 16 fe 01 13 05 11 05 2d b7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}