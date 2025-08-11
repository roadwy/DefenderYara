
rule Trojan_BAT_SnakeKeylogger_SJHA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SJHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 08 } //3
		$a_03_1 = {02 11 05 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 07 72 ?? ?? ?? 70 28 ?? 00 00 0a 2c 08 11 09 1f 64 fe 02 2b 01 } //2
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}