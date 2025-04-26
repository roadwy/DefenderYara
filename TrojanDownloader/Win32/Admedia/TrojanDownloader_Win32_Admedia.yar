
rule TrojanDownloader_Win32_Admedia{
	meta:
		description = "TrojanDownloader:Win32/Admedia,SIGNATURE_TYPE_PEHSTR_EXT,17 00 15 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 63 6e 6e 69 63 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f } //10 http://www.ccnnic.com/download/
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 6f 77 65 72 6e 75 6d 31 32 33 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f } //10 http://www.powernum123.com/download/
		$a_01_2 = {68 77 77 70 77 77 77 77 77 77 77 70 6f 77 65 72 6e 75 6d 31 32 33 77 63 6f 6d 77 64 6f 77 6e 6c 6f 61 64 77 70 6e 78 70 77 66 } //10 hwwpwwwwwwwpowernum123wcomwdownloadwpnxpwf
		$a_00_3 = {52 75 00 00 6f 6e 00 00 73 69 00 00 65 72 00 00 74 56 00 00 65 6e 00 00 } //10
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 44 6f 6e 67 74 69 61 6e 5c } //1 Software\Dongtian\
		$a_01_5 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e } //1 Windows\CurrentVersion\Policies\Explorer\Run
		$a_00_6 = {39 31 35 33 32 39 36 35 38 32 30 36 34 31 34 39 42 30 43 36 45 44 30 35 30 31 38 43 39 44 30 37 } //1 9153296582064149B0C6ED05018C9D07
		$a_00_7 = {6d 69 63 72 6f 61 70 6d 64 64 74 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=21
 
}