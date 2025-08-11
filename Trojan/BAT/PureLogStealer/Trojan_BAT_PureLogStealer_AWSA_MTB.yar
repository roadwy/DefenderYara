
rule Trojan_BAT_PureLogStealer_AWSA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AWSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 1a 8d ?? 00 00 01 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 16 13 07 2b 15 11 07 11 05 11 06 11 07 11 04 11 07 59 6f ?? 00 00 0a 58 13 07 11 07 11 04 32 e5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}