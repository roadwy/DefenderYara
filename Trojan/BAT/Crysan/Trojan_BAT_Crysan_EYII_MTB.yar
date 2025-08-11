
rule Trojan_BAT_Crysan_EYII_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EYII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 2a 1d 11 0b 5f 91 13 1e 11 1e 19 62 11 1e 1b 63 60 d2 13 1e 11 06 11 0b 11 06 11 0b 91 11 1e 61 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}