
rule Trojan_BAT_PureLogStealer_AWPB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AWPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 2c 0b 72 ?? ?? 00 70 73 ?? 00 00 0a 7a 00 20 82 00 00 00 0b 06 8e 69 17 da 17 d6 8d ?? 00 00 01 0c 06 08 06 8e 69 28 ?? ?? 00 0a 00 08 8e 69 17 da 13 04 16 13 05 2b 10 08 11 05 08 11 05 91 07 61 9c 11 05 1b d6 13 05 11 05 11 04 31 ea } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}