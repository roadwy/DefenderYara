
rule Trojan_BAT_Rozena_PSRM_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PSRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 72 01 00 00 70 0a 73 0f 00 00 0a 0b 14 0c 00 07 06 6f 10 00 00 0a 0c 00 de 1c 13 06 00 72 49 00 00 70 11 06 6f 11 00 00 0a 28 12 00 00 0a 28 13 00 00 0a 00 de 53 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}