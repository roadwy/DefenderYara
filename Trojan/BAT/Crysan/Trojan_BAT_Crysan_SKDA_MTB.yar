
rule Trojan_BAT_Crysan_SKDA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SKDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 13 11 1e 11 09 91 13 27 11 1e 11 09 11 23 11 27 61 11 1b 19 58 61 11 2a 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}