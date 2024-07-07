
rule Trojan_BAT_RemLoader_RPX_MTB{
	meta:
		description = "Trojan:BAT/RemLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 06 5a 00 0e 00 3c 07 47 07 0a 00 67 07 a2 02 0a 00 82 07 a2 02 0a 00 97 07 a2 02 0a 00 c5 07 a2 02 06 00 f4 07 da 00 06 00 } //1
		$a_01_1 = {44 65 66 75 6e 65 20 4c 53 } //1 Defune LS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}