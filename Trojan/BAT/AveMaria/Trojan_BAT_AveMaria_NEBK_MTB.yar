
rule Trojan_BAT_AveMaria_NEBK_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 28 56 00 00 0a 02 28 0f 00 00 06 73 0d 00 00 06 7b 07 00 00 04 02 28 61 00 00 06 20 00 01 00 00 14 14 14 28 69 00 00 06 } //5
		$a_01_1 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 28 00 4d 00 61 00 6e 00 61 00 67 00 65 00 64 00 29 00 } //4 Debugger detected (Managed)
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}