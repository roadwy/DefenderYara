
rule Trojan_BAT_VIPKeylogger_ZZQ_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.ZZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 8f ?? 00 00 01 25 47 09 11 07 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 09 1f 1f 5a 08 11 07 91 58 20 00 01 00 00 5d 0d 11 07 17 58 13 07 } //6
		$a_01_1 = {08 11 06 11 06 1f 25 5a 20 00 01 00 00 5d d2 9c 11 06 17 58 13 06 11 06 08 8e 69 32 e3 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*5) >=11
 
}