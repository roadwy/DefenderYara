
rule Trojan_BAT_AveMaria_NEDT_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 2a 11 00 2a 00 d0 0d 00 00 01 28 05 00 00 0a 02 02 28 06 00 00 06 28 07 00 00 06 74 0b 00 00 01 72 3f 00 00 70 28 06 00 00 0a 6f 07 00 00 0a 16 9a 28 01 00 00 2b 6f 09 00 00 0a 26 20 01 00 00 00 } //10
		$a_01_1 = {57 00 64 00 61 00 61 00 79 00 61 00 6a 00 72 00 63 00 70 00 } //5 Wdaayajrcp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}