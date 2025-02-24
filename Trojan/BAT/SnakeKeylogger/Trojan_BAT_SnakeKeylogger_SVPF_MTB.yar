
rule Trojan_BAT_SnakeKeylogger_SVPF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SVPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 07 6f ?? 00 00 0a 13 05 16 2d ef 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 1c 2c 1d 11 07 09 16 09 8e 69 6f ?? 00 00 0a 16 2d 0e 11 06 6f ?? 00 00 0a 28 ?? 00 00 0a 13 08 de 27 11 07 2c 07 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}