
rule Trojan_BAT_PureLogStealer_NAAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.NAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 13 00 07 09 07 09 91 20 ?? ?? 00 00 59 d2 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 04 11 04 2d e1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}