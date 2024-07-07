
rule Trojan_BAT_Bobik_AMMA_MTB{
	meta:
		description = "Trojan:BAT/Bobik.AMMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 11 d2 13 31 11 11 1e 63 d1 13 11 11 1b 11 09 91 13 20 11 1b 11 09 11 20 11 23 61 11 1e 19 58 61 11 31 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}