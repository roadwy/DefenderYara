
rule Trojan_BAT_PureLogStealer_TSAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.TSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0d 2b 17 00 02 11 0d 02 11 0d 91 20 ?? ?? 00 00 59 d2 9c 00 11 0d 17 58 13 0d 11 0d 02 8e 69 fe 04 13 0e 11 0e 2d dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}