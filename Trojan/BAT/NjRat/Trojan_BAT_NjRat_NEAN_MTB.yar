
rule Trojan_BAT_NjRat_NEAN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e cb 00 00 04 7e ca 00 00 04 7e c6 00 00 04 28 90 01 01 00 00 06 7e 29 00 00 04 08 07 28 90 01 01 00 00 06 28 90 01 01 00 00 06 13 04 7e cc 00 00 04 7e ca 00 00 04 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}