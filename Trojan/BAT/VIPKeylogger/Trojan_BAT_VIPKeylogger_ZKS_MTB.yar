
rule Trojan_BAT_VIPKeylogger_ZKS_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.ZKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 11 20 58 13 33 02 11 31 11 35 6f ?? 00 00 0a 13 38 12 38 28 ?? 00 00 0a 06 61 d2 13 39 12 38 28 ?? 00 00 0a 06 61 d2 13 3a 12 38 28 ?? 00 00 0a 06 61 d2 13 3b 11 39 07 1f 1f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}