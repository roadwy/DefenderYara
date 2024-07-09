
rule Trojan_BAT_DCRat_PTJI_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PTJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 18 06 02 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 06 28 ?? 00 00 0a 26 02 28 ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}