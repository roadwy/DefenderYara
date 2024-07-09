
rule Trojan_BAT_SnakeKeylogger_SPAP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 20 40 f4 c1 53 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 20 3f f4 c1 53 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 73 f6 00 00 0a 0b 14 fe 06 2a 05 00 06 73 2a 03 00 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 75 8b 00 00 1b 73 03 02 00 0a 0c 08 11 04 16 73 2b 03 00 0a 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}