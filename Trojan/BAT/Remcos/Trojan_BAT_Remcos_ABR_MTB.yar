
rule Trojan_BAT_Remcos_ABR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 19 13 05 38 ?? ff ff ff 02 28 ?? 00 00 0a 0b 19 13 05 38 ?? ff ff ff 02 28 ?? 00 00 0a 0b 19 13 05 38 ?? ff ff ff 02 28 ?? 00 00 0a 0b 19 13 05 38 ?? ff ff ff 06 17 58 0a } //5
		$a_03_1 = {02 8c 15 00 00 1b 03 04 6f ?? 01 00 0a 0b 1d 13 04 38 ?? ff ff ff 06 17 58 0a 05 25 5a 05 58 18 5d 2c 12 11 06 1f 2b 94 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}