
rule Trojan_BAT_injuke_NEAA_MTB{
	meta:
		description = "Trojan:BAT/injuke.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 17 00 00 06 20 e4 1d 29 81 20 47 c7 f9 e2 61 7e be 00 00 04 7b 34 01 00 04 61 28 48 00 00 06 6f 26 00 00 0a 13 09 20 00 00 00 00 7e 75 00 00 04 7b 11 00 00 04 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}