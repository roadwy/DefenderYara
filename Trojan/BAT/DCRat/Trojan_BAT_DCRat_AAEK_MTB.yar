
rule Trojan_BAT_DCRat_AAEK_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AAEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 16 73 90 01 01 00 00 0a 0b 16 0c 00 0f 00 08 20 00 04 00 00 58 28 90 01 01 00 00 2b 00 07 02 08 20 00 04 00 00 6f 90 01 01 00 00 0a 0d 08 09 58 0c 00 09 20 00 04 00 00 fe 04 16 fe 01 13 04 11 04 2d cc 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}