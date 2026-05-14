
rule Trojan_BAT_SnakeKeylogger_ZFI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 5d 6f ?? 00 00 0a 13 10 19 8d ?? 00 00 01 25 16 12 10 28 ?? 00 00 0a 9c 25 17 12 10 28 ?? 00 00 0a 9c 25 18 12 10 28 ?? 00 00 0a 9c 13 11 11 05 17 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}