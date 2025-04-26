
rule Trojan_BAT_SnakeKeylogger_SGPZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SGPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 12 00 00 0a 0b 07 72 ?? 00 00 70 73 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 08 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}