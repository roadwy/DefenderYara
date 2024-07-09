
rule Trojan_BAT_CoinStealer_MBDN_MTB{
	meta:
		description = "Trojan:BAT/CoinStealer.MBDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 02 1a 02 8e 69 1a 59 6f ?? 00 00 0a 28 6b 00 00 06 0c de 2d } //1
		$a_01_1 = {45 43 4e 47 72 6d 38 31 44 58 66 6d 54 41 51 69 } //1 ECNGrm81DXfmTAQi
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}