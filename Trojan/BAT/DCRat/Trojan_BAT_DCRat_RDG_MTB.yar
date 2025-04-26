
rule Trojan_BAT_DCRat_RDG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 14 11 15 11 13 11 15 9a 28 0e 00 00 0a 9c 11 15 17 58 13 15 11 15 11 13 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}