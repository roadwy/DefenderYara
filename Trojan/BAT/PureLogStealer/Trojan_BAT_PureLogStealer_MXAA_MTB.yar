
rule Trojan_BAT_PureLogStealer_MXAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 09 d4 11 07 09 d4 91 07 07 06 95 07 08 95 58 20 ff 00 00 00 5f 95 61 28 ?? 00 00 0a 9c 09 17 6a 58 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}