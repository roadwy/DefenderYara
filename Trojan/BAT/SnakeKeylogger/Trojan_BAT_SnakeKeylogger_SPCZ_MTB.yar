
rule Trojan_BAT_SnakeKeylogger_SPCZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 03 00 00 04 6f ?? ?? ?? 0a 02 0e 04 04 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}