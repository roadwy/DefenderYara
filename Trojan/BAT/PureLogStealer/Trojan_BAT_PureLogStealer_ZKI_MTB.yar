
rule Trojan_BAT_PureLogStealer_ZKI_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ZKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 05 06 7b ?? 00 00 04 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 17 13 04 12 00 28 ?? 00 00 06 2b 8f 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}