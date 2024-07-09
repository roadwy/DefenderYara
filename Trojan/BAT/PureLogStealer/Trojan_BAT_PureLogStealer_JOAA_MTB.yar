
rule Trojan_BAT_PureLogStealer_JOAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.JOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 01 11 00 11 02 94 02 11 02 11 01 28 ?? ?? 00 06 58 9e } //2
		$a_03_1 = {11 00 11 02 94 02 11 02 11 01 28 ?? ?? 00 06 58 11 00 11 01 94 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}