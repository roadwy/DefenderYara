
rule Trojan_BAT_SnakeKeylogger_SLO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SLO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 20 00 7e 01 00 0d 07 08 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_SnakeKeylogger_SLO_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SLO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 74 1e 00 00 01 11 05 11 0a 75 07 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 07 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 22 00 00 0a 26 19 13 0e 38 4c fe ff ff } //1
		$a_01_1 = {24 43 32 38 35 42 39 34 37 2d 41 36 33 44 2d 34 46 43 38 2d 42 43 31 37 2d 45 39 41 34 46 31 44 37 38 32 43 30 } //1 $C285B947-A63D-4FC8-BC17-E9A4F1D782C0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}