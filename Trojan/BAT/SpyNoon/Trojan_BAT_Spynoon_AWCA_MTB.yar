
rule Trojan_BAT_Spynoon_AWCA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AWCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 06 08 04 28 ?? 00 00 06 00 08 17 58 0c 00 08 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0d 09 2d d6 } //3
		$a_03_1 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 13 05 00 11 05 13 06 16 13 07 2b 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}