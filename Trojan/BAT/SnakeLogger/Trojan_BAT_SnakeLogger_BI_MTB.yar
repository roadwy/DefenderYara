
rule Trojan_BAT_SnakeLogger_BI_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0f 00 28 ?? 00 00 0a 1a 5d 0f 00 28 ?? 00 00 0a 9c 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 28 ?? 00 00 06 0b 07 28 ?? 00 00 06 0c 2b 00 08 2a } //3
		$a_03_1 = {0a 02 04 05 28 ?? 00 00 06 0b 0e 04 03 6f ?? 00 00 0a 28 ?? 00 00 06 0c 03 07 08 28 ?? 00 00 06 00 2a } //2
		$a_00_2 = {20 00 01 00 00 5a 6a 0a 02 03 28 } //3
		$a_03_3 = {07 17 58 0b 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 05 fe 04 2b 01 16 0c 08 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_00_2  & 1)*3+(#a_03_3  & 1)*2) >=10
 
}