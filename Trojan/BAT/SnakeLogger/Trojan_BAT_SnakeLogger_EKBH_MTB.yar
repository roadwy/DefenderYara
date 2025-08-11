
rule Trojan_BAT_SnakeLogger_EKBH_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.EKBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 11 26 17 94 58 13 18 11 26 16 94 11 26 17 94 58 1f 19 5d 16 fe 01 13 19 11 26 17 94 19 5d 2c 17 11 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}