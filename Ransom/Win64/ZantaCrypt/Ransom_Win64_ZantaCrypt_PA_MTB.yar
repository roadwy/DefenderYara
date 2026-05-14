
rule Ransom_Win64_ZantaCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/ZantaCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 00 41 00 4e 00 54 00 41 00 5f 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //2 ZANTA_READ_ME.txt
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 5a 00 61 00 6e 00 74 00 61 00 55 00 6c 00 74 00 69 00 6d 00 61 00 4d 00 75 00 74 00 65 00 78 00 } //3 Global\ZantaUltimaMutex
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}