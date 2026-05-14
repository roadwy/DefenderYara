
rule Trojan_BAT_Spynoon_AVOB_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AVOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 13 05 03 06 6f ?? 00 00 0a 59 13 06 11 05 09 12 04 28 ?? 00 00 06 13 07 11 07 16 91 13 08 11 08 1a 62 11 08 1a 63 60 d2 13 08 11 08 1a 62 11 08 1a 63 60 d2 13 08 06 11 08 6f ?? 00 00 0a 11 06 17 59 25 13 06 16 } //5
		$a_03_1 = {0a 06 16 0f 00 28 ?? 00 00 0a 03 61 d2 9c 06 17 0f 00 28 ?? 00 00 0a 03 61 d2 9c 06 18 0f 00 28 ?? 00 00 0a 03 61 d2 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}