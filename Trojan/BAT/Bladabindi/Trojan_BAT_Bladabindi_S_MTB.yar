
rule Trojan_BAT_Bladabindi_S_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.S!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c9 7c 2a 8b 35 88 2c 41 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 15 24 20 41 00 8d 04 80 03 c0 2b d0 8a 04 0a 30 04 0e 41 3b 0d a0 2c 41 00 76 c9 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_BAT_Bladabindi_S_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.S!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 34 00 00 0a 72 47 01 00 70 28 35 00 00 0a 17 8d 28 00 00 01 25 16 1f 3a 9d 6f 36 00 00 0a 0a 06 8e 69 17 da 0c 16 0b 2b 14 06 16 9a 80 0e 00 00 04 06 17 9a 80 18 00 00 04 07 17 d6 0b 07 08 31 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}