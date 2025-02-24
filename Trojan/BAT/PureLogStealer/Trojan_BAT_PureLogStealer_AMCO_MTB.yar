
rule Trojan_BAT_PureLogStealer_AMCO_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AMCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 28 06 00 00 2b } //4
		$a_03_1 = {1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0c 03 08 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 03 08 1e 63 20 ff 00 00 00 5f d2 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}