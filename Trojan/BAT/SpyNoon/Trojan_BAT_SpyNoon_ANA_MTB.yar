
rule Trojan_BAT_SpyNoon_ANA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ANA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 14 11 04 06 07 06 91 09 06 09 8e 69 5d 91 61 d2 9c 06 17 58 0a 06 07 8e 69 32 e6 } //2
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 73 00 65 00 63 00 74 00 69 00 6f 00 6e 00 53 00 69 00 6d 00 } //1 IntersectionSim
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}