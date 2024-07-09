
rule Trojan_BAT_PureLogStealer_LRAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.LRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 72 41 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 9b 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 06 13 05 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}