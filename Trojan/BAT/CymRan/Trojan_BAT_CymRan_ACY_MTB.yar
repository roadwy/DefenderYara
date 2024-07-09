
rule Trojan_BAT_CymRan_ACY_MTB{
	meta:
		description = "Trojan:BAT/CymRan.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 1f 00 08 09 9a 28 ?? 00 00 0a 28 ?? 00 00 06 13 04 11 04 2c 06 00 06 17 58 0a 00 00 09 17 58 0d } //1
		$a_03_1 = {08 11 06 9a 28 ?? 00 00 0a 6f ?? 00 00 06 00 08 11 06 9a 28 ?? 00 00 06 13 08 11 08 2c 06 00 07 17 58 0b 00 00 00 11 06 17 58 13 06 11 06 08 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}