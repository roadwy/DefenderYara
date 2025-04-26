
rule Trojan_BAT_DCRat_PSOV_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PSOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 72 23 00 00 70 14 d0 02 00 00 02 28 14 00 00 0a 18 8d 31 00 00 01 25 16 16 14 28 18 00 00 0a a2 25 17 17 14 28 18 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}