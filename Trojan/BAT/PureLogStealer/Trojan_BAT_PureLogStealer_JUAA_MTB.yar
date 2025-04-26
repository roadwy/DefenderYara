
rule Trojan_BAT_PureLogStealer_JUAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.JUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 04 8e 69 28 ?? 00 00 06 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}