
rule Trojan_BAT_Tedy_AMBH_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1e 63 d1 13 17 11 11 11 09 91 13 25 11 11 11 09 11 26 11 25 61 19 11 1b 58 61 11 2d 61 d2 9c 17 11 09 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}