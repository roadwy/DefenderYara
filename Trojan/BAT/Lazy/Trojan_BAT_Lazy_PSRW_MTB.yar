
rule Trojan_BAT_Lazy_PSRW_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSRW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 02 73 90 01 01 01 00 0a 0d 09 08 16 73 e2 01 00 0a 13 04 11 04 28 90 01 01 01 00 0a 73 90 01 01 01 00 0a 13 05 11 05 6f 90 01 01 01 00 0a 0a de 2c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}