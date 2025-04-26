
rule TrojanDownloader_Win32_MMViewer{
	meta:
		description = "TrojanDownloader:Win32/MMViewer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 6d 76 69 65 77 65 72 2e 63 6f 6d 00 2f 70 6f 73 74 2f [0-30] 25 25 25 78 00 [0-10] 6c 6f 63 61 6c 68 6f 73 74 3a 38 30 38 30 00 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 } //4
		$a_01_1 = {68 74 74 70 70 6f 73 74 5f 64 6c 6c 2e 44 4c 4c } //2 httppost_dll.DLL
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}