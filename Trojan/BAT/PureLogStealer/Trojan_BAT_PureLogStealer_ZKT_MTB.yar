
rule Trojan_BAT_PureLogStealer_ZKT_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ZKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 91 06 09 93 28 ?? 00 00 0a 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 20 2e 5b 50 7c 00 fe 0e 06 00 00 fe 0d 06 00 48 68 20 2e 5b 6f 15 00 fe 0e 06 00 fe 0d 06 00 48 68 fe 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}