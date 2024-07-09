
rule Trojan_BAT_DCRat_ADR_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {14 fe 01 0a 06 2c 41 00 7e 59 00 00 0a 0b 00 28 cc 00 00 0a 6f cd 00 00 0a 6f ce 00 00 0a 0b 00 de 05 26 00 00 de 00 07 28 0c 00 00 0a 0c 08 2c 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DCRat_ADR_MTB_2{
	meta:
		description = "Trojan:BAT/DCRat.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 29 07 06 08 16 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 17 58 13 04 11 04 09 fe 04 13 06 11 06 2d cc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}