
rule Trojan_BAT_SnakeKeylogger_EKEQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EKEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 11 39 fe 01 13 3a 11 3a 13 3b 11 3b 2c 0b 00 03 11 39 ?? ?? ?? ?? ?? 00 00 00 11 37 17 58 13 37 11 37 11 35 8e 69 fe 04 13 3c 11 3c 2d bb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}