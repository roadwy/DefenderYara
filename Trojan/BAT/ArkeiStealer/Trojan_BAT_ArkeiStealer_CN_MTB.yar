
rule Trojan_BAT_ArkeiStealer_CN_MTB{
	meta:
		description = "Trojan:BAT/ArkeiStealer.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 02 7b 71 00 00 04 28 90 01 04 28 90 01 04 58 7d 90 01 04 00 02 7b 90 01 04 0c 02 08 17 58 7d 90 01 04 02 7b 90 01 04 02 7b 90 01 04 1d 1f 0e 6f 6f 01 00 0a fe 04 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}