
rule TrojanDownloader_Win32_VB_QF{
	meta:
		description = "TrojanDownloader:Win32/VB.QF,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 64 00 6d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 64 00 69 00 72 00 2e 00 70 00 68 00 70 00 3f 00 6f 00 3d 00 } //5 http://ldmdownload.com/redir.php?o=
		$a_00_1 = {26 00 61 00 66 00 66 00 3d 00 } //2 &aff=
		$a_01_2 = {53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 } //1 SHDocVwCtl.WebBrowser
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}