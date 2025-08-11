
rule Trojan_BAT_Snakekeylogger_ANK_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.ANK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 02 7d ?? 01 00 04 06 03 7d ?? 01 00 04 06 04 7d ?? 01 00 04 00 06 28 ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 15 6e 61 15 6e 61 7d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}