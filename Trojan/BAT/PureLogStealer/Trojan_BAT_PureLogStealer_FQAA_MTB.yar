
rule Trojan_BAT_PureLogStealer_FQAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.FQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 2c eb dd 90 01 01 00 00 00 26 dd 00 00 00 00 11 04 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 11 04 6f 90 01 01 00 00 0a 13 05 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}