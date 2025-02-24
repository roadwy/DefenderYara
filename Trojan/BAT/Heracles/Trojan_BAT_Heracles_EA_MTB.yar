
rule Trojan_BAT_Heracles_EA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 07 28 04 00 00 06 26 16 13 08 2b 14 11 06 11 08 11 04 11 08 91 28 12 00 00 0a 11 08 17 58 13 08 11 08 11 04 8e 69 32 e4 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}