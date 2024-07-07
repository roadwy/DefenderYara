
rule Trojan_BAT_PureLogStealer_HPAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.HPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0a 06 28 90 01 01 00 00 0a 02 06 28 90 01 01 00 00 0a 7d 90 01 01 00 00 04 dd 90 01 01 00 00 00 26 dd 00 00 00 00 06 2c d9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}