
rule Trojan_BAT_SnakeKeylogger_ABSK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 13 05 38 ?? ff ff ff 02 8c ?? 00 00 1b 03 04 6f ?? 01 00 0a 0b 17 13 05 38 ?? ff ff ff 06 17 58 0a 0e 04 25 5a 0d 0e 04 09 58 0d 1a 13 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_SnakeKeylogger_ABSK_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 6f ?? 01 00 0a 16 03 6f ?? 01 00 0a 0a 12 00 28 ?? 01 00 0a 73 ?? 01 00 0a a2 25 17 03 6f ?? 01 00 0a 17 03 6f ?? 01 00 0a 0a 12 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_SnakeKeylogger_ABSK_MTB_3{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 06 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 0d } //5
		$a_03_1 = {07 1f 63 58 0b 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 59 25 0d 16 fe 02 16 fe 01 2d 3c 03 12 0c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}