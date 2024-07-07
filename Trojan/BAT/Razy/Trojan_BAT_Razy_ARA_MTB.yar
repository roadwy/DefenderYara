
rule Trojan_BAT_Razy_ARA_MTB{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 10 11 04 07 08 9a 6f 90 01 03 0a 13 04 08 17 90 01 01 0c 08 11 05 31 eb 11 04 07 08 9a 90 00 } //2
		$a_01_1 = {4c 00 61 00 6e 00 7a 00 61 00 64 00 6f 00 72 00 } //1 Lanzador
		$a_01_2 = {50 00 61 00 69 00 6c 00 61 00 } //1 Paila
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Razy_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 18 73 23 00 00 0a 13 04 09 11 04 6f 90 01 03 0a de 0c 11 04 2c 07 11 04 6f 90 01 03 0a dc 02 7b 0b 00 00 04 28 90 00 } //2
		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 6e 00 64 00 65 00 72 00 53 00 74 00 75 00 62 00 2e 00 65 00 78 00 65 00 } //1 BlackBinderStub.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Razy_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 05 2b 3c 12 05 28 70 00 00 0a 0b 00 07 28 2a 00 00 06 16 fe 01 13 04 11 04 2d 04 07 0d de 47 07 28 2b 00 00 06 0c 08 7e 5a 00 00 0a 28 71 00 00 0a 16 fe 01 13 04 11 04 2d 04 } //1
		$a_01_1 = {13 04 2b 2b 12 04 28 70 00 00 0a 0b 00 07 28 29 00 00 06 0c 08 28 73 00 00 0a 0d 09 2d 08 03 08 6f 74 00 00 0a 00 07 03 28 2c 00 00 06 00 00 12 04 28 72 00 00 0a 0d 09 2d ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}