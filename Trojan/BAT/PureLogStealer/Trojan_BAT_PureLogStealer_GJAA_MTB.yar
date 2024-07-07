
rule Trojan_BAT_PureLogStealer_GJAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.GJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 16 07 8e 69 6f 90 01 01 00 00 0a dd 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}