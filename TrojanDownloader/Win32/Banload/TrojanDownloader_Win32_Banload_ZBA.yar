
rule TrojanDownloader_Win32_Banload_ZBA{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZBA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {84 c0 74 0c 6a 00 68 ?? ?? ?? ?? e8 ad 95 fb ff 68 c4 09 00 00 e8 1f fa fb ff ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 } //1
		$a_00_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 73 79 73 74 65 6d 2e 65 78 65 } //1 c:\windows\system\system.exe
		$a_02_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6b 72 65 68 65 72 2e 74 76 2f 64 68 65 73 2f 69 6d 61 67 65 73 2f 69 6d 61 67 65 73 2f [0-05] 2e 73 63 72 } //1
		$a_00_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 63 6f 6d 61 6e 64 73 32 2e 65 78 65 } //1 c:\windows\system\comands2.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}