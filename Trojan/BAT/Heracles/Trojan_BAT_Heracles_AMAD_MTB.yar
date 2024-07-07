
rule Trojan_BAT_Heracles_AMAD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 10 d2 13 35 11 10 1e 63 d1 13 10 11 1c 11 09 91 13 25 11 1c 11 09 11 23 11 25 61 11 19 19 58 61 11 35 61 d2 9c 11 25 13 19 17 11 09 58 13 09 11 09 11 27 32 a4 } //1
		$a_01_1 = {11 2e 11 17 11 16 11 17 91 9d 17 11 17 58 13 17 11 17 11 18 32 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}