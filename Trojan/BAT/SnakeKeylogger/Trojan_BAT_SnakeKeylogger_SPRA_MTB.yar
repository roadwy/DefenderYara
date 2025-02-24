
rule Trojan_BAT_SnakeKeylogger_SPRA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 03 16 03 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 de 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}