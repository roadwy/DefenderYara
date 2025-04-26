
rule Trojan_BAT_Jalapeno_EAJF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.EAJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 28 28 00 00 0a 07 6f 29 00 00 0a 1e 5b 8d 3e 00 00 01 13 04 1e 11 04 16 1e 28 2a 00 00 0a 73 2b 00 00 0a 13 05 04 07 08 11 04 6f 2c 00 00 0a 16 73 2d 00 00 0a 13 06 11 06 11 05 28 39 01 00 06 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Jalapeno_EAJF_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.EAJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 02 6f 1f 00 00 0a 28 20 00 00 0a 0c 02 16 08 6f 21 00 00 0a 0d 09 1f 0a 6f 22 00 00 0a 13 04 11 04 16 31 0e 08 07 33 0a 09 16 11 04 6f 21 00 00 0a 0d 06 09 6f 23 00 00 0a 6f 24 00 00 0a 02 09 6f 1f 00 00 0a 6f 25 00 00 0a 6f 26 00 00 0a 10 00 02 6f 1f 00 00 0a 16 30 a5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}