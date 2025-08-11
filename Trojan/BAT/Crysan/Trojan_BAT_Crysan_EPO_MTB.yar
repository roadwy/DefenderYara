
rule Trojan_BAT_Crysan_EPO_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 2a 11 0b 1d 5f 91 13 1e 11 1e 19 62 11 1e 1b 63 60 d2 13 1e 11 06 11 0b 11 06 11 0b 91 11 1e 61 d2 9c 17 11 0b 58 13 0b 11 0b 11 07 32 d1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}