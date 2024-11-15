
rule Trojan_BAT_SnakeKeylogger_SKL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SKL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 07 28 aa 00 00 06 0c 04 03 6f a0 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19 8d 7e 00 00 01 25 16 12 02 28 a1 00 00 0a 9c 25 17 12 02 28 a2 00 00 0a 9c 25 18 12 02 28 a3 00 00 0a 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}