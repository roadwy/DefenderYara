
rule Trojan_BAT_CoinStealer_MBDN_MTB{
	meta:
		description = "Trojan:BAT/CoinStealer.MBDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 08 02 1a 02 8e 69 1a 59 6f 90 01 01 00 00 0a 28 6b 00 00 06 0c de 2d 90 00 } //01 00 
		$a_01_1 = {45 43 4e 47 72 6d 38 31 44 58 66 6d 54 41 51 69 } //00 00  ECNGrm81DXfmTAQi
	condition:
		any of ($a_*)
 
}