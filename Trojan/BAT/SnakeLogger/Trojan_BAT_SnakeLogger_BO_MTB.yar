
rule Trojan_BAT_SnakeLogger_BO_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 58 1d 5d 16 fe 01 13 06 11 06 13 07 11 07 2c 0c 08 11 05 1f 20 5b 28 ?? ?? 00 06 00 02 07 11 05 03 04 28 ?? ?? 00 06 00 00 11 05 17 58 13 05 11 05 02 6f ?? 00 00 0a 2f 0b 03 6f ?? ?? 00 0a 04 fe 04 2b 01 16 13 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}