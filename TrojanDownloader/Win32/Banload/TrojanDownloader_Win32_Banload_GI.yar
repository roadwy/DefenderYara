
rule TrojanDownloader_Win32_Banload_GI{
	meta:
		description = "TrojanDownloader:Win32/Banload.GI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 2e 65 78 65 } //1 c:\WindowsDefender.exe
		$a_02_1 = {68 74 74 70 3a 2f 2f 74 77 6f 78 69 73 2e 77 65 62 2e 63 65 64 61 6e 74 2e 63 6f 6d 2f [0-08] 2e 67 69 66 } //1
		$a_00_2 = {56 69 73 75 61 6c 69 7a 61 64 6f 72 20 64 65 20 69 6d 61 67 65 6e 73 20 65 20 66 61 78 20 64 6f 20 57 69 6e 64 6f 77 73 2e } //1 Visualizador de imagens e fax do Windows.
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}