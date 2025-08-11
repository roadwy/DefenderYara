
rule Trojan_BAT_Stealer_EACC_MTB{
	meta:
		description = "Trojan:BAT/Stealer.EACC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 9a 13 05 11 05 73 89 01 00 0a 6f 94 01 00 0a 13 06 11 06 6f 47 00 00 0a 1f 10 33 13 06 11 06 28 da 00 00 0a 13 07 11 05 11 07 28 5e 04 00 06 11 04 17 58 13 04 11 04 09 8e 69 32 c1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}