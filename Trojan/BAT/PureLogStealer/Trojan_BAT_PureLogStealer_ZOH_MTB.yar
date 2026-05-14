
rule Trojan_BAT_PureLogStealer_ZOH_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ZOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {1e 13 08 38 ?? ff ff ff 1f 0d 2b f5 07 11 04 02 11 04 91 20 94 00 00 00 61 9c 00 19 13 08 38 ?? ff ff ff 00 07 11 04 02 11 04 91 9c 00 19 13 08 38 ?? ff ff ff 11 04 17 d6 13 04 1f 0c } //6
		$a_03_1 = {02 8e 69 17 da 17 d6 8d ?? 00 00 01 0b 02 8e 69 17 da 0d 11 09 20 08 02 00 00 94 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}