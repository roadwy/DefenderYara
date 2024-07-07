
rule Trojan_BAT_Zusy_AMBH_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1e 63 d1 13 12 11 14 11 09 91 13 20 11 14 11 09 11 20 11 24 61 11 1c 19 58 61 11 35 61 d2 9c 11 09 17 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}