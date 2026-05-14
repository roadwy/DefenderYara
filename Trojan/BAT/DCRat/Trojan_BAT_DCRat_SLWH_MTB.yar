
rule Trojan_BAT_DCRat_SLWH_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SLWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 17 28 e0 01 00 06 02 1a 8d 76 00 00 01 28 da 01 00 06 02 73 99 00 00 0a 28 de 01 00 06 02 28 e5 01 00 06 28 ea 01 00 06 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}