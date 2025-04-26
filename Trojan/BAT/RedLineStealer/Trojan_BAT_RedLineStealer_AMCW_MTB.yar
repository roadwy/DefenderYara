
rule Trojan_BAT_RedLineStealer_AMCW_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 ?? 28 ?? 00 00 0a 9c 25 18 12 ?? 28 ?? 00 00 0a 9c 11 ?? 28 } //4
		$a_03_1 = {1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 ?? 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 ?? 20 ff 00 00 00 5f d2 9c } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}