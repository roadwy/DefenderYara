
rule Trojan_BAT_PureLogStealer_ACBA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ACBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 39 9e 00 00 00 26 06 72 ?? 02 00 70 28 ?? 00 00 0a 72 ?? 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 2b 29 2b 2e 2b 30 2b 31 2b 33 16 2b 37 2b 39 8e 69 6f ?? 00 00 0a 11 04 } //3
		$a_03_1 = {16 2d f6 08 13 05 1e 2c f0 19 2c f4 de 3b 28 ?? 00 00 06 2b d0 13 04 2b ce 09 2b cd 11 04 2b cb 6f ?? 00 00 0a 2b c6 11 04 2b c5 6f ?? 00 00 0a 2b c0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}