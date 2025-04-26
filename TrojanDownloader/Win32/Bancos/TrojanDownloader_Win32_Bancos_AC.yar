
rule TrojanDownloader_Win32_Bancos_AC{
	meta:
		description = "TrojanDownloader:Win32/Bancos.AC,SIGNATURE_TYPE_PEHSTR_EXT,29 00 1f 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 37 39 2e 31 32 35 2e 37 2e 32 32 31 2f [0-10] 2e 74 73 74 } //10
		$a_00_1 = {2f 63 20 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 20 33 30 20 2f 63 20 22 45 73 74 65 20 63 6f 6d 70 75 74 61 64 6f 72 } //10 /c shutdown /r /t 30 /c "Este computador
		$a_00_2 = {5c 47 62 50 6c 75 67 69 6e 5c 67 62 70 64 69 73 74 2e 64 6c 6c } //10 \GbPlugin\gbpdist.dll
		$a_00_3 = {41 20 66 65 72 72 61 6d 65 6e 74 61 20 64 65 20 72 65 6d 6f e7 e3 6f 20 64 65 20 73 6f 66 74 77 61 72 65 20 6d 61 6c 20 69 6e 74 65 6e 63 69 6f 6e 61 64 6f 20 64 61 20 4d 69 63 72 6f } //10
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1) >=31
 
}