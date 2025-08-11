
rule Trojan_BAT_PureLogStealer_AWVA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AWVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0a 2b 38 04 28 ?? 03 00 06 0b 2b 37 28 ?? 03 00 06 25 06 28 ?? 03 00 06 25 07 28 ?? 03 00 06 25 1f 0f 28 ?? 01 00 06 28 ?? 03 00 06 25 1c 28 ?? 01 00 06 28 ?? 03 00 06 0c 2b 0e 1f c1 1f cb 32 c2 2b 06 1f 85 1f 2c 32 c3 08 28 ?? 03 00 06 0d 09 02 16 28 ?? 01 00 06 02 8e 69 28 ?? 03 00 06 13 04 de 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}