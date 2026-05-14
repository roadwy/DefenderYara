
rule Trojan_BAT_Exnet_MKA_MTB{
	meta:
		description = "Trojan:BAT/Exnet.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {2c 75 00 06 72 5e 02 00 70 1f 28 6f 1a 00 00 0a 13 08 06 72 76 02 00 70 1f 28 6f 1a 00 00 0a 13 09 06 72 8e 02 00 70 1f 28 6f 1a 00 00 0a 13 0a 11 08 2d 02 2b 0a 11 08 14 14 28 1b 00 00 0a 00 11 09 2d 02 2b 13 } //15
		$a_01_1 = {0b 07 2c 30 00 06 72 ac 02 00 70 1f 28 6f 22 00 00 0a 0c 08 2d 02 2b 1b 08 14 17 8d 13 00 00 01 25 16 7e 23 00 00 0a 8c 23 00 00 01 a2 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}