
rule TrojanDownloader_Win32_Banload_ACD{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 73 5c 41 56 47 5c 41 56 47 } //1 :\Arquivos de programs\AVG\AVG
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4e 69 63 72 6f 73 6f 66 74 2e 65 78 65 } //1 Software\Classes\Applications\Nicrosoft.exe
		$a_00_2 = {5c 41 74 61 6c 68 6f 5f 2e 70 69 66 } //1 \Atalho_.pif
		$a_00_3 = {5c 69 6e 69 63 69 6f 2e 65 78 65 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 68 6f 6f 6b 44 6c 6c 2e 64 6c 6c } //1
		$a_02_4 = {4e 6f 41 73 49 6e 76 6f 6b 65 72 [0-0a] 5c 4d 53 44 4f 53 2e 70 69 66 } //1
		$a_02_5 = {5c 4d 53 44 4f 53 [0-0a] 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 42 65 68 6f 6c 64 65 72 2e 65 78 65 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}