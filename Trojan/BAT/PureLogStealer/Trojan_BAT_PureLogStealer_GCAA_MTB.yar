
rule Trojan_BAT_PureLogStealer_GCAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.GCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 16 11 00 8e 69 28 ?? 00 00 0a 20 00 00 00 00 7e ?? 1d 00 04 7b ?? 1d 00 04 3a ?? ff ff ff 26 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}