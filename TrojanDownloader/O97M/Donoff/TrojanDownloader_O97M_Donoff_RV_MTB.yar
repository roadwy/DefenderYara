
rule TrojanDownloader_O97M_Donoff_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c 53 79 73 74 65 6d 33 32 5c 5c 63 6d 64 2e 65 78 65 20 2f 63 20 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 42 3a 5c 48 61 63 6b 5c 4f 66 66 69 63 65 5c 65 76 69 6c 6f 66 66 69 63 65 5c 65 6d 61 79 2e 74 78 74 } //1 Shell ("C:\\Windows\\System32\\cmd.exe /c certutil -decode B:\Hack\Office\eviloffice\emay.txt
		$a_01_1 = {42 3a 5c 48 61 63 6b 5c 4f 66 66 69 63 65 5c 65 76 69 6c 6f 66 66 69 63 65 5c 65 6d 61 79 2e 65 78 65 22 29 0d 0a 45 6e 64 20 53 75 62 } //1
		$a_01_2 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}