
rule Trojan_BAT_Heracles_MKA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 9a 0b 7e 09 00 00 04 07 28 03 00 00 06 0a 06 28 31 00 00 0a 2d 27 72 44 0e 00 70 06 17 8d 13 00 00 01 13 04 11 04 16 1f 2f 9d 11 04 6f 32 00 00 0a 28 2f 00 00 0a 80 08 00 00 04 2b 0a 09 17 58 0d 09 08 8e 69 } //20
		$a_01_1 = {0a 06 02 7d 43 00 00 04 06 03 7d 44 00 00 04 06 fe 06 25 00 00 06 73 99 00 00 0a 28 9a 00 00 0a 26 2a } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}