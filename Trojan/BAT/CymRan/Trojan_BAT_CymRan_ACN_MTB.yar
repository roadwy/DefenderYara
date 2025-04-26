
rule Trojan_BAT_CymRan_ACN_MTB{
	meta:
		description = "Trojan:BAT/CymRan.ACN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 07 2b 3a 06 6f ?? 00 00 0a 13 08 09 11 08 d2 6e 00 72 5a 17 00 70 28 ?? 00 00 0a 11 07 5a 00 72 5e 17 00 70 28 ?? 00 00 0a 5f 62 60 0d 11 07 00 72 29 00 00 70 28 ?? 00 00 0a 58 13 07 11 07 } //2
		$a_03_1 = {64 d2 9c 11 07 11 05 25 00 72 29 00 00 70 28 ?? 00 00 0a 58 13 05 11 0b 00 72 e2 1a 00 70 28 ?? 00 00 0a 64 d2 9c 08 11 0a 8f 61 00 00 01 25 4b 11 0b 61 54 11 0a } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}