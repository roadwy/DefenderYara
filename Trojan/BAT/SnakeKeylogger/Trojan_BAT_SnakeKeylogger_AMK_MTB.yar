
rule Trojan_BAT_SnakeKeylogger_AMK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 09 11 04 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 0a 06 11 05 17 73 ?? 00 00 0a 0c 08 [0-14] 8e 69 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}