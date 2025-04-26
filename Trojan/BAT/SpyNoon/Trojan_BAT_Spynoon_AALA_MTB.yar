
rule Trojan_BAT_Spynoon_AALA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 61 0f 00 28 ?? 00 00 0a 61 d2 9c 25 17 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 5f 60 d2 9c 25 18 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 66 66 5f d2 9c 0a 03 06 6f ?? 00 00 0a 00 2a } //3
		$a_03_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}