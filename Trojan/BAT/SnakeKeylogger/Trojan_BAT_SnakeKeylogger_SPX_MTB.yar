
rule Trojan_BAT_SnakeKeylogger_SPX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 08 8d 54 00 00 01 0d 16 13 05 2b 71 00 07 19 11 05 5a 6f ?? ?? ?? 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 } //2
		$a_01_1 = {67 65 74 5f 4d 61 72 6c 69 65 63 65 5f 41 6e 64 72 61 64 61 5f 5f 34 30 } //1 get_Marliece_Andrada__40
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}