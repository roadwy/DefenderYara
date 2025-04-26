
rule Trojan_BAT_Snakekeylogger_PHP_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.PHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 2c 4f 00 0f 00 28 ?? 01 00 0a 0f 00 28 ?? 01 00 0a 61 0f 00 28 ?? 01 00 0a 61 d2 0d 09 28 ?? 00 00 06 00 04 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 01 00 0a 9c 25 17 0f 00 28 ?? 01 00 0a 9c 25 18 0f 00 28 ?? 01 00 0a 9c 6f ?? 01 00 0a 00 00 2b 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}