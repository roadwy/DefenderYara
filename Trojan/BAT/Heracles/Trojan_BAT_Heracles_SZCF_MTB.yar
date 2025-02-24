
rule Trojan_BAT_Heracles_SZCF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SZCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 15 11 1f 11 09 91 13 25 11 1f 11 09 11 25 11 27 61 11 1d 19 58 61 11 33 61 d2 9c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}