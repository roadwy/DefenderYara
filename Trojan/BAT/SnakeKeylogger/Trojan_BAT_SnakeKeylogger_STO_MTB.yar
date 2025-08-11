
rule Trojan_BAT_SnakeKeylogger_STO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.STO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 06 0e 07 0e 06 1b 23 ea e4 97 9b 77 e3 f9 3f 28 ?? 00 00 06 0b 02 03 04 06 05 0e 04 07 0e 08 23 39 b4 c8 76 be 9f e6 3f 28 ?? 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 2d b3 } //2
		$a_03_1 = {00 05 07 0e 06 23 00 00 00 00 00 00 e0 3f 19 28 ?? 00 00 06 0c 02 05 07 6f ?? 00 00 0a 0d 03 04 09 08 06 05 07 23 9a 99 99 99 99 99 b9 3f 17 28 ?? 00 00 06 00 0e 04 05 07 23 7b 14 ae 47 e1 7a 84 3f 17 28 ?? 00 00 06 00 00 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 04 11 04 2d 97 } //2
		$a_81_2 = {51 4c 44 54 44 44 5f 46 50 54 2e 4d 61 69 6e 66 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //2 QLDTDD_FPT.Mainform.resources
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}