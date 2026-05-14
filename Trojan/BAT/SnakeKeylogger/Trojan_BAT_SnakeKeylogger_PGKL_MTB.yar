
rule Trojan_BAT_SnakeKeylogger_PGKL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PGKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8c 11 00 00 1b 03 04 6f ?? 00 00 0a 0b 18 13 06 38 ?? ff ff ff 06 17 58 0a 20 b8 07 00 00 0d 20 a7 01 00 00 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}