
rule TrojanDownloader_Win32_Banload_JV{
	meta:
		description = "TrojanDownloader:Win32/Banload.JV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 72 72 6f 20 34 30 34 21 } //1 Erro 404!
		$a_01_1 = {73 79 73 74 65 6d 33 32 5c 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 system32\iexplorer.exe
		$a_01_2 = {45 78 70 6c 6f 72 65 72 00 68 74 74 70 3a 2f 2f 6e 61 72 75 74 6f 32 30 30 39 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}