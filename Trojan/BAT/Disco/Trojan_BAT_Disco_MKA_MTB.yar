
rule Trojan_BAT_Disco_MKA_MTB{
	meta:
		description = "Trojan:BAT/Disco.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 11 11 6f 70 01 00 06 25 11 17 6f 72 01 00 06 25 11 12 6f 74 01 00 06 25 11 13 6f 76 01 00 06 25 11 14 6f 7a 01 00 06 25 11 16 6f 78 01 00 06 } //20
		$a_01_1 = {0b 07 6f d1 01 00 0a 16 31 0c 06 72 b6 2a 00 70 07 6f d2 01 00 0a } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}