
rule Trojan_BAT_PureLogStealer_MKV_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 0a 6f ?? 00 00 0a 20 00 00 00 00 7e 85 00 00 04 7b b5 00 00 04 3a 0f 00 00 00 26 20 01 00 00 00 38 04 00 00 00 fe 0c 03 00 45 04 00 00 00 2d 00 00 00 05 00 00 00 40 00 00 00 63 00 00 00 38 28 00 00 00 11 04 11 07 6f ?? 00 00 0a 20 00 00 00 00 7e 85 00 00 04 7b a5 00 00 04 39 c9 ff ff ff 26 20 00 00 00 00 38 be ff ff ff 11 04 6f ?? 00 00 0a 13 05 20 02 00 00 00 38 ab ff ff ff 03 72 c7 00 00 70 11 05 11 09 16 11 09 8e 69 6f ?? 00 00 0a 6f ?? 00 00 06 20 03 00 00 00 38 88 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}