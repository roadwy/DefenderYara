
rule Trojan_BAT_DCRat_SLUU_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SLUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 1a 28 1d 00 00 0a 00 28 1e 00 00 0a 72 01 00 00 70 28 1f 00 00 0a 6f 20 00 00 0a 0c 08 28 21 00 00 0a 0d 7e 07 00 00 04 2d 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}