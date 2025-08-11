
rule Trojan_BAT_SnakeKeylogger_BAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 11 07 11 08 91 6f 8a 00 00 0a 11 08 17 58 13 08 11 08 11 06 32 e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}