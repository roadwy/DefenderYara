
rule TrojanDownloader_Win32_Tijcont_A{
	meta:
		description = "TrojanDownloader:Win32/Tijcont.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 76 6f 68 63 73 74 2e 65 78 65 00 [0-40] 44 6f 77 6e 6c 6f 61 64 00 } //1
		$a_01_1 = {44 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 D:\windows\system32\taskmgr.exe
		$a_03_2 = {3a 31 33 31 34 2f 74 6a [0-01] 2f 43 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}