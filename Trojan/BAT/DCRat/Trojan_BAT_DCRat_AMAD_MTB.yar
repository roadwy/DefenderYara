
rule Trojan_BAT_DCRat_AMAD_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0c 06 08 16 1f 10 6f 90 01 01 00 00 0a 26 07 08 6f 90 01 01 01 00 0a 06 07 6f 90 01 01 01 00 0a 16 73 90 01 01 01 00 0a 13 08 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}