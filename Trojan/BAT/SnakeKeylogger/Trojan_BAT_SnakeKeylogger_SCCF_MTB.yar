
rule Trojan_BAT_SnakeKeylogger_SCCF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SCCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06 03 11 06 09 } //3
		$a_03_1 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}