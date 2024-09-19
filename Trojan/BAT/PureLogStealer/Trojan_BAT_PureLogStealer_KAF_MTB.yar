
rule Trojan_BAT_PureLogStealer_KAF_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 3a 08 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}