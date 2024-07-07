
rule Trojan_BAT_AveMaria_NEEP_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 05 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 72 90 01 01 00 00 70 7e 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b de 03 26 de cf 90 00 } //10
		$a_01_1 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //2 DynamicInvoke
		$a_01_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //2 GetByteArrayAsync
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}