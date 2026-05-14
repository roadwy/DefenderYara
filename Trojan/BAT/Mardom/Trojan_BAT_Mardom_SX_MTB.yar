
rule Trojan_BAT_Mardom_SX_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 25 00 00 0a 0a 28 26 00 00 0a 0b 16 0c 2b 47 07 08 9a 6f 27 00 00 0a 6f 28 00 00 0a 6f 29 00 00 0a 0d 2b 1a 09 6f 2a 00 00 0a 13 04 06 11 04 6f 2b 00 00 0a 6f 2c 00 00 0a 6f 2d 00 00 0a 09 6f 2e 00 00 0a 2d de de 0a 09 2c 06 09 6f 2f 00 00 0a dc 08 17 58 0c 08 07 8e 69 32 b3 06 2a } //20
		$a_01_1 = {73 75 00 00 06 0a 06 03 7d 45 00 00 04 02 7b 09 00 00 04 06 7b 45 00 00 04 6f 5d 00 00 0a 06 7b 45 00 00 04 06 fe 06 76 00 00 06 73 5e 00 00 0a 6f 5f 00 00 0a 26 2a } //10
		$a_01_2 = {41 74 68 65 6e 61 } //30 Athena
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*30) >=60
 
}