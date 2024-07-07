
rule Trojan_BAT_PureLogStealer_AFAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 91 61 28 90 01 02 00 06 90 01 01 08 20 87 10 00 00 58 20 86 10 00 00 59 90 01 01 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}