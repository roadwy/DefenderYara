
rule Trojan_BAT_VIPKeylogger_PHS_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.PHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 03 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}