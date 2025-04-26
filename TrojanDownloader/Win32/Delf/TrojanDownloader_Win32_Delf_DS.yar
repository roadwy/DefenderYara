
rule TrojanDownloader_Win32_Delf_DS{
	meta:
		description = "TrojanDownloader:Win32/Delf.DS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {2e 6e 65 6f 70 6f 69 6e 74 2e 63 6f 2e 6b 72 00 5c 50 72 6f 67 72 61 6d 46 69 6c 65 73 } //2
		$a_01_2 = {41 30 30 30 30 30 30 31 00 } //1
		$a_01_3 = {4f 6e 65 4c 6f 61 64 65 72 2e 65 78 65 00 } //1
		$a_01_4 = {4e 65 6f 50 6f 69 6e 74 2e 69 6e 69 00 } //1
		$a_01_5 = {54 77 6f 4c 6f 61 64 65 72 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}