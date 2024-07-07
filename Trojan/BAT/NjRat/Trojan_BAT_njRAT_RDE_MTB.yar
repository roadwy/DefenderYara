
rule Trojan_BAT_njRAT_RDE_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDE!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 61 72 61 6d 65 74 65 72 69 7a 65 64 54 68 72 65 61 64 53 74 61 72 74 } //1 ParameterizedThreadStart
		$a_01_1 = {02 50 06 02 50 06 91 03 06 03 6f 07 00 00 0a 5d 6f 08 00 00 0a 61 d2 9c 06 17 58 0a 06 02 50 8e 69 fe 04 0b 07 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}