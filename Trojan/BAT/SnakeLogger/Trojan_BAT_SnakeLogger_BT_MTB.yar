
rule Trojan_BAT_SnakeLogger_BT_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 13 0a 11 0a 19 fe 04 16 fe 01 13 10 11 10 2c 48 00 11 06 16 2f 07 11 08 16 fe 04 2b 01 16 } //4
		$a_03_1 = {9c 25 17 12 09 28 ?? 00 00 0a 9c 25 18 12 09 28 ?? 00 00 0a 9c } //1
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}