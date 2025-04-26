
rule Trojan_BAT_Remcos_EC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {14 16 9a 26 16 2d f9 72 8e 01 00 70 6f 68 00 00 0a 26 02 28 69 00 00 0a 0a 28 3e 00 00 0a 06 16 06 8e 69 6f 6a 00 00 0a 2a } //1
		$a_01_1 = {02 74 27 00 00 01 6f 29 00 00 0a 6f 2a 00 00 0a 6f 2b 00 00 0a 72 fe 01 00 70 72 01 00 00 70 6f 2c 00 00 0a 0a dd 6e 00 00 00 dd 06 00 00 00 } //1
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}