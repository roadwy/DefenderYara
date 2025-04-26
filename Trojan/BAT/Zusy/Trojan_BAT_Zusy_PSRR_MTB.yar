
rule Trojan_BAT_Zusy_PSRR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 72 bb 00 00 70 6f 0b 00 00 0a 17 8d 0d 00 00 01 13 07 11 07 16 1f 0a 9d 11 07 6f 0c 00 00 0a 0b 06 6f 0d 00 00 0a 00 16 8d 0e 00 00 01 0c 00 07 13 08 16 13 09 2b 43 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}