
rule Trojan_BAT_PureLogStealer_AMQA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AMQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 2c 07 1a 8d ?? 00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 16 2d 0b 07 16 28 ?? 00 00 0a 19 2c f2 0c 06 16 73 ?? 00 00 0a 0d 2b 1d 1d 2c 10 8d ?? 00 00 01 2b 16 2b 18 2b 19 16 2b 1a 2b 1b 26 11 04 13 05 1e 2c f9 de 2c 08 2b e0 13 04 2b e6 09 2b e5 11 04 2b e3 08 2b e3 6f ?? 00 00 0a 2b de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}