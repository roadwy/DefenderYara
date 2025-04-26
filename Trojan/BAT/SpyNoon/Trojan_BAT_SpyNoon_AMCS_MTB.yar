
rule Trojan_BAT_SpyNoon_AMCS_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c } //4
		$a_03_1 = {1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 ?? 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 ?? 20 ff 00 00 00 5f d2 9c 6f } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}