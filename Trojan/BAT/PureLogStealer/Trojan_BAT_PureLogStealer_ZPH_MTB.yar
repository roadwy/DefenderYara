
rule Trojan_BAT_PureLogStealer_ZPH_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ZPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 05 19 8d ?? 00 00 01 25 16 12 05 28 ?? 00 00 0a 9c 25 17 12 05 28 ?? 00 00 0a 9c 25 18 12 05 28 ?? 00 00 0a 9c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}