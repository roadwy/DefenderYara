
rule Trojan_BAT_AveMaria_MA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c 08 16 08 8e 69 28 17 00 00 0a 08 0d de 0a 07 2c 06 06 28 18 00 00 0a dc } //5
		$a_01_1 = {9e 07 06 11 05 94 58 0b 11 05 17 58 13 05 11 05 1f 0a 32 c0 } //5
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //2 DownloadData
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2) >=12
 
}
rule Trojan_BAT_AveMaria_MA_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 95 a2 29 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 44 00 00 00 11 } //10
		$a_01_1 = {6c 6c 64 2e 65 65 72 6f 63 73 6d } //1 lld.eerocsm
		$a_01_2 = {6e 69 61 4d 6c 6c 44 72 6f 43 5f } //1 niaMllDroC_
		$a_01_3 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //1 .edom SOD ni nur eb tonnac margorp sihT!
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}