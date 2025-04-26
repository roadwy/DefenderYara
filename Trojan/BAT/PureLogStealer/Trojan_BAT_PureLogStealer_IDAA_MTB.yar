
rule Trojan_BAT_PureLogStealer_IDAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.IDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 0d 9c 08 11 13 7b ?? 00 00 04 91 08 07 91 58 20 00 01 00 00 5d 13 0e 05 11 0c 8f ?? 00 00 01 25 71 ?? 00 00 01 08 11 0e 7e ?? 00 00 04 28 ?? 03 00 06 a5 ?? 00 00 01 61 d2 81 ?? 00 00 01 1f 0a 8d ?? 00 00 01 13 0f 16 13 10 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}