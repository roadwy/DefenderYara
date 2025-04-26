
rule Trojan_BAT_ClipBanker_ABR_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 95 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 40 00 00 00 17 00 00 00 3c 00 00 00 74 00 00 00 42 00 00 00 } //3
		$a_01_1 = {43 6c 69 70 62 6f 61 72 64 } //1 Clipboard
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}