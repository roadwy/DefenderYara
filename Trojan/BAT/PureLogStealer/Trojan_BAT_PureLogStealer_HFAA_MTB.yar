
rule Trojan_BAT_PureLogStealer_HFAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.HFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2a 00 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 17 8d ?? 00 00 01 25 16 20 ?? 00 00 00 9c 07 17 5d 91 61 d2 9c 00 07 17 58 0b 07 02 7b ?? 00 00 04 8e 69 fe 04 0c 08 2d c7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}