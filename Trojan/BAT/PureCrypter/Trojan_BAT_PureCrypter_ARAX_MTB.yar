
rule Trojan_BAT_PureCrypter_ARAX_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 12 02 28 ?? ?? ?? 0a 13 06 12 02 28 ?? ?? ?? 0a 13 07 03 11 05 16 61 d2 6f ?? ?? ?? 0a 00 03 11 06 16 61 d2 6f ?? ?? ?? 0a 00 03 11 07 16 61 d2 6f ?? ?? ?? 0a 00 2b 15 03 6f ?? ?? ?? 0a 19 58 04 31 03 16 2b 01 17 13 08 11 08 2d a9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_PureCrypter_ARAX_MTB_2{
	meta:
		description = "Trojan:BAT/PureCrypter.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 17 58 20 ff 00 00 00 5f 13 09 11 07 11 04 11 09 95 58 20 ff 00 00 00 5f 13 07 02 11 04 11 09 8f ?? ?? ?? 01 11 04 11 07 8f ?? ?? ?? 01 28 ?? ?? ?? 06 00 11 04 11 09 95 11 04 11 07 95 58 20 ff 00 00 00 5f 13 11 11 06 19 5e 16 fe 01 13 12 11 12 2c 10 00 11 08 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 08 00 09 11 06 07 11 06 91 11 04 11 11 95 61 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 00 11 06 6e 09 8e 69 6a fe 04 13 13 11 13 3a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}