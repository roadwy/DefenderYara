
rule Trojan_BAT_PureLogStealer_RVD_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 13 09 12 08 28 ?? 00 00 0a 13 0a 12 08 28 ?? 00 00 0a 13 0b 11 09 11 06 28 ?? 00 00 06 13 09 11 0a 11 06 17 58 28 ?? 00 00 06 13 0a 11 0b 11 06 18 58 28 ?? 00 00 06 13 0b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}