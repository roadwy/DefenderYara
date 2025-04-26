
rule TrojanDownloader_Win32_Banload_KO{
	meta:
		description = "TrojanDownloader:Win32/Banload.KO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 52 52 4f 52 20 31 30 58 30 32 30 } //1 ERROR 10X020
		$a_01_1 = {70 72 6f 62 6c 65 6d 61 20 70 65 72 73 69 73 74 69 72 2c 20 63 6f 6e 74 61 63 74 65 } //1 problema persistir, contacte
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 48 65 6c 70 5c 63 73 72 73 73 73 2e 65 78 65 } //1 C:\WINDOWS\Help\csrsss.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}