
rule Trojan_BAT_Crysan_AYC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 2b 1d 09 02 11 05 6f ?? 00 00 0a 06 61 d1 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 11 05 17 58 13 05 11 05 11 04 } //2
		$a_03_1 = {1e 5a 0a 06 1f 40 33 16 7e ?? 00 00 0a 7e ?? 00 00 04 28 ?? 00 00 06 80 06 00 00 04 2b 19 06 1f 20 33 14 7e ?? 00 00 0a 7e } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}