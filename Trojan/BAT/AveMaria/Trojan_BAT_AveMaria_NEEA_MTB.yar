
rule Trojan_BAT_AveMaria_NEEA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 2a 16 2c 2e 26 2b 2e 2b 2f 2b 34 16 2d f7 2b 32 16 08 8e 69 28 ?? 00 00 0a 08 0d de 52 28 ?? 00 00 0a 2b c9 28 ?? 00 00 0a 2b d4 6f ?? 00 00 0a 2b cf 0b 2b d0 07 2b cf 28 ?? 00 00 0a 2b ca 0c 2b c9 08 2b cb } //10
		$a_01_1 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73 } //2 SmartAssembly.Attributes
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}