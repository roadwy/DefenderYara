
rule TrojanDownloader_BAT_Banload_Y{
	meta:
		description = "TrojanDownloader:BAT/Banload.Y,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 6f 64 20 4c 6f 61 64 65 72 } //1 \Mod Loader
		$a_01_1 = {5c 54 65 73 74 65 73 20 4c 6f 61 64 65 73 } //1 \Testes Loades
		$a_03_2 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1
		$a_03_3 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 ?? ?? 50 00 6f 00 72 00 74 00 75 00 67 00 75 00 } //1
		$a_03_4 = {2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}
rule TrojanDownloader_BAT_Banload_Y_2{
	meta:
		description = "TrojanDownloader:BAT/Banload.Y,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //2
		$a_03_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 61 00 72 00 6d 00 73 00 76 00 63 00 33 00 32 00 2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //2
		$a_03_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 66 00 69 00 78 00 2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //2
		$a_03_3 = {2e 00 65 00 6e 00 63 00 ?? ?? 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-10] 2e 00 65 00 6e 00 63 00 ?? ?? 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 61 00 72 00 6d 00 73 00 76 00 63 00 33 00 32 00 2e 00 63 00 70 00 6c 00 } //2
		$a_03_4 = {50 52 4f 4a 45 54 4f 20 [0-30] 4c 6f 61 64 65 72 73 [0-10] 45 78 65 6d 70 6c 6f 20 55 6d [0-04] 5c 6f 62 6a 5c 44 65 62 75 67 5c } //1
		$a_01_5 = {44 3a 5c 45 78 65 6d 70 6c 6f 20 55 6d 20 31 5c 6f 62 6a 5c 44 65 62 75 67 5c } //1 D:\Exemplo Um 1\obj\Debug\
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}