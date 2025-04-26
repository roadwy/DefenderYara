
rule Trojan_BAT_Spynoon_ABEW_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ABEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de } //3
		$a_01_1 = {43 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 72 00 2e 00 50 00 4f 00 49 00 55 00 59 00 48 00 4a 00 4b 00 } //1 CurrencyConverter.POIUYHJK
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}