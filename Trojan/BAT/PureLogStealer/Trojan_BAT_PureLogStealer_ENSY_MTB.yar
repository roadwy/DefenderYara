
rule Trojan_BAT_PureLogStealer_ENSY_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ENSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 11 0b 11 07 91 ?? ?? ?? ?? ?? 11 07 17 58 13 07 11 07 11 09 32 e9 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}