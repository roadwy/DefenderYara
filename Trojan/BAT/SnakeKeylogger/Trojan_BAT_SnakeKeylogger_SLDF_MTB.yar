
rule Trojan_BAT_SnakeKeylogger_SLDF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SLDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 11 06 6f ?? ?? ?? 0a 13 07 07 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 0f 20 fb 00 00 00 91 1f 09 5b 13 0e 38 55 fe ff ff 00 07 6f ?? ?? ?? 0a 20 00 40 01 00 fe 04 13 08 11 08 2c 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}