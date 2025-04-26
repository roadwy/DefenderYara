
rule Backdoor_BAT_Remcos_ABV_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 17 a2 09 09 03 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 38 00 00 00 } //5
		$a_01_1 = {51 57 4b 44 4f 57 51 4b 44 4f 51 4b 4f 44 } //1 QWKDOWQKDOQKOD
		$a_01_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}