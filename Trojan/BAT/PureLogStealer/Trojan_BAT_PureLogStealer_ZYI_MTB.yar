
rule Trojan_BAT_PureLogStealer_ZYI_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ZYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 05 4a 0e 04 4a 6f ?? 00 00 0a 81 ?? 00 00 01 04 0e 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 0e 08 2d 02 2b 0e 0e 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}