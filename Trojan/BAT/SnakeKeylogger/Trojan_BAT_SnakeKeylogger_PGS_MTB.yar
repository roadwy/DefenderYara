
rule Trojan_BAT_SnakeKeylogger_PGS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 20 00 7c 01 00 0d 07 08 09 28 ?? 00 00 06 00 17 8d ?? 00 00 01 25 16 1f 4c 9d 17 8d ?? 00 00 01 25 16 1f 6f 9d 28 ?? 00 00 2b 17 8d ?? 00 00 01 25 16 1f 61 9d 28 ?? 00 00 2b 17 8d ?? 00 00 01 25 16 1f 64 9d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}