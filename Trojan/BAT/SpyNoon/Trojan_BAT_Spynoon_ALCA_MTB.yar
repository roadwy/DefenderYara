
rule Trojan_BAT_Spynoon_ALCA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ALCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 d0 } //3
		$a_03_1 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}