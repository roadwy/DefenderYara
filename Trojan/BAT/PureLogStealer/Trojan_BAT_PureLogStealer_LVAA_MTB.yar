
rule Trojan_BAT_PureLogStealer_LVAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.LVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 04 91 11 10 61 11 05 11 11 91 59 13 12 11 12 20 00 01 00 00 58 13 13 11 05 11 04 11 13 d2 9c 11 04 17 58 13 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}