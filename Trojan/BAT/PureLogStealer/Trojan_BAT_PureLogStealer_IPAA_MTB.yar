
rule Trojan_BAT_PureLogStealer_IPAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.IPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 07 06 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 28 ?? 00 00 06 73 ?? 00 00 0a 13 04 00 11 04 08 16 73 ?? 00 00 0a 13 05 00 11 05 09 6f ?? 00 00 0a 00 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}