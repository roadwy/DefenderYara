
rule Trojan_BAT_PureLogStealer_AGEA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AGEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 0b 11 0b 1f 7b 61 20 ff 00 00 00 5f 13 0c 11 0c 20 c8 01 00 00 58 20 00 01 00 00 5e 13 0c 11 0c 2c 04 11 0c 2b 01 17 13 0c 09 11 0a 07 11 0a 91 11 04 11 0b 95 61 28 ?? 00 00 0a 9c 00 11 0a 17 58 13 0a 11 0a 07 8e 69 fe 04 13 0d 11 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}