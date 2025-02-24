
rule Trojan_BAT_DarkVision_AMCL_MTB{
	meta:
		description = "Trojan:BAT/DarkVision.AMCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {1e 62 60 0f ?? 28 ?? 00 00 0a 60 0a 02 06 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 02 06 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 02 06 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 2a } //4
		$a_03_1 = {9c 25 18 0f ?? 28 ?? 00 00 0a 9c 0b 02 07 04 28 ?? 00 00 2b 6f ?? 00 00 0a 2a } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}