
rule Trojan_BAT_SnakeKeylogger_STSG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.STSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 18 fe 04 16 fe 01 13 05 11 05 2c 0e 03 12 00 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 19 fe 01 13 06 11 06 2c 0e 03 12 00 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}