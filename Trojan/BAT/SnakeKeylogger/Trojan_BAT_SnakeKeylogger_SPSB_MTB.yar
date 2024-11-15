
rule Trojan_BAT_SnakeKeylogger_SPSB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 2c 00 00 0a 0c 08 07 17 73 2d 00 00 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 04 dd 27 00 00 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}