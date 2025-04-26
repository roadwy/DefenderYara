
rule Trojan_BAT_PureLogStealer_HBAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.HBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 01 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 01 8e 69 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}