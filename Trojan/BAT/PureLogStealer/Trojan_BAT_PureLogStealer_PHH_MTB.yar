
rule Trojan_BAT_PureLogStealer_PHH_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.PHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 09 6c 5a 69 26 02 07 08 6f ?? 00 00 0a 13 04 03 06 6f ?? 00 00 0a 59 13 05 12 04 28 ?? 00 00 0a 13 06 06 11 06 09 61 d2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}