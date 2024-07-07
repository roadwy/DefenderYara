
rule TrojanDownloader_O97M_Donoff_HSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.HSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 50 6a 6f 61 6f 31 35 37 38 2f 55 70 63 72 79 70 74 65 72 2f 6d 61 69 6e 2f 45 78 70 70 6c 6f 69 69 69 74 65 72 } //1 raw.githubusercontent.com/Pjoao1578/Upcrypter/main/Expploiiiter
		$a_01_1 = {2e 52 75 6e 20 22 57 53 63 72 69 70 74 2e 65 78 65 20 51 6c 70 4b 78 2e 76 62 73 } //1 .Run "WScript.exe QlpKx.vbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_HSM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.HSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 22 66 79 66 2f 71 74 73 6e 22 29 } //1 ("fyf/qtsn")
		$a_01_1 = {28 22 66 79 66 2f 65 69 68 67 69 75 62 63 30 69 67 74 77 68 74 73 75 78 73 78 66 67 66 6b 69 69 68 6e 6b 69 74 68 69 7a 65 69 68 74 67 6f 69 68 67 6b 7a 67 6b 76 68 6a 6c 69 68 67 65 68 6b 68 65 6c 63 65 7b 67 68 67 30 69 7a 75 6f 70 67 6e 70 64 30 6e 70 64 2f 74 62 6f 6a 65 6f 62 73 70 75 64 62 73 75 2f 78 78 78 30 30 3b 74 71 75 75 69 22 29 } //1 ("fyf/eihgiubc0igtwhtsuxsxfgfkiihnkithizeihtgoihgkzgkvhjlihgehkhelce{ghg0izuopgnpd0npd/tbojeobspudbsu/xxx00;tquui")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}