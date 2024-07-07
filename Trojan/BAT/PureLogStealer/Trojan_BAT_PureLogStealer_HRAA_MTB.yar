
rule Trojan_BAT_PureLogStealer_HRAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.HRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 13 04 38 1a 00 00 00 00 28 90 01 01 00 00 06 13 04 11 04 28 90 01 01 00 00 0a dd 90 01 01 00 00 00 26 dd 00 00 00 00 11 04 2c e2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}