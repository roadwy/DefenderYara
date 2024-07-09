
rule Trojan_BAT_BladaInjector_MTB{
	meta:
		description = "Trojan:BAT/BladaInjector!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {0a 06 0b 16 0c 90 0a 10 00 73 ?? 00 00 0a 0a 06 0b 16 0c 07 12 02 28 ?? 01 00 0a 06 20 10 27 00 00 28 ?? 01 00 0a 26 de } //1
		$a_02_1 = {25 47 03 06 03 90 0a 10 00 02 06 8f ?? 00 00 01 25 47 03 06 03 8e 69 5d 91 06 04 03 8e 69 5d 58 04 5f 61 d2 61 d2 52 } //1
		$a_02_2 = {61 03 61 0a 90 0a 10 00 02 20 ?? ?? ?? ?? 61 03 61 0a 7e 03 00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 17 13 0e 38 7d ff ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}