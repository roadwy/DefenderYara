
rule Trojan_BAT_Bulz_PSRQ_MTB{
	meta:
		description = "Trojan:BAT/Bulz.PSRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 0f 00 00 0a 72 01 00 00 70 28 10 00 00 0a 0a 06 0b 2b 00 07 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}