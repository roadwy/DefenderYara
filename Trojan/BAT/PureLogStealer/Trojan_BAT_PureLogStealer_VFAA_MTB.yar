
rule Trojan_BAT_PureLogStealer_VFAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.VFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 11 02 02 11 02 91 11 01 11 02 11 01 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}