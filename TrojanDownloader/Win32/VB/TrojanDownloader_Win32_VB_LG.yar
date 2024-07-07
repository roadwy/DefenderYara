
rule TrojanDownloader_Win32_VB_LG{
	meta:
		description = "TrojanDownloader:Win32/VB.LG,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 4a 00 20 00 4f 00 20 00 45 00 5c 00 42 00 6f 00 77 00 74 00 73 00 5c 00 4d 00 2d 00 79 00 2d 00 4c 00 2d 00 69 00 2d 00 72 00 2d 00 61 00 2d 00 74 00 } //1 Desktop\J O E\Bowts\M-y-L-i-r-a-t
		$a_01_1 = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 69 00 6e 00 67 00 } //1 Redirecting
		$a_01_2 = {53 00 74 00 61 00 72 00 74 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 } //1 Start downl
		$a_01_3 = {53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 } //1 SHDocVwCtl.WebBrowser
		$a_01_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}