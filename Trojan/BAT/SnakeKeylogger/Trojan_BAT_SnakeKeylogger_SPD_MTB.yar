
rule Trojan_BAT_SnakeKeylogger_SPD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 20 00 80 01 00 8d 71 00 00 01 0b 06 72 d5 05 00 70 6f 90 01 03 0a 74 08 00 00 1b 16 07 16 20 00 c0 00 00 28 90 01 03 0a 00 06 72 db 05 00 70 6f 90 01 03 0a 74 08 00 00 1b 16 90 00 } //3
		$a_01_1 = {53 69 78 58 46 6f 75 72 } //1 SixXFour
		$a_01_2 = {72 75 6e 55 73 65 72 54 75 72 6e } //1 runUserTurn
		$a_01_3 = {72 75 6e 54 75 72 6e 65 73 } //1 runTurnes
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}