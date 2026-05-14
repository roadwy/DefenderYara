
rule Trojan_BAT_PureLogStealer_ACOB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ACOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 09 2c 05 38 9f 00 00 00 20 86 00 00 00 0a 16 0b 2b 0d 02 07 02 07 91 06 61 9c 07 1b d6 0b 00 07 02 8e 69 fe 04 13 04 11 04 2d e7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}