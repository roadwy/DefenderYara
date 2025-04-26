
rule Trojan_BAT_SnakeKeylogger_SZZF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SZZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 01 28 ?? 01 00 0a 9c 25 17 0f 01 28 ?? 01 00 0a 9c 25 18 0f 01 28 ?? 01 00 0a 9c 6f ?? 01 00 0a 00 00 } //3
		$a_03_1 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 01 00 0a 59 0d 03 08 09 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}