
rule Trojan_BAT_SnakeKeylogger_EE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 04 00 00 "
		
	strings :
		$a_03_0 = {14 0b 14 0c 28 90 01 03 06 74 90 01 03 1b 0c 08 17 28 90 01 03 06 a2 08 18 72 90 01 03 70 a2 08 16 28 90 01 03 06 a2 02 7b 90 01 03 04 08 28 90 01 03 0a 26 08 0a 2b 00 06 2a 90 00 } //20
		$a_81_1 = {24 63 38 34 30 61 36 61 35 2d 36 33 31 30 2d 34 36 38 62 2d 38 63 63 63 2d 38 39 34 66 65 34 64 31 30 37 61 36 } //5 $c840a6a5-6310-468b-8ccc-894fe4d107a6
		$a_81_2 = {57 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 57 } //1 W__________W
		$a_81_3 = {58 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 58 } //1 X__________X
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=27
 
}