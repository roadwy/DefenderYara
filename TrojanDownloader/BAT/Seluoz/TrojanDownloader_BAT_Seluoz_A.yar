
rule TrojanDownloader_BAT_Seluoz_A{
	meta:
		description = "TrojanDownloader:BAT/Seluoz.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {2f 00 72 00 75 00 6e 00 2e 00 70 00 68 00 70 00 } //1 /run.php
		$a_01_2 = {5c 00 61 00 2e 00 65 00 78 00 65 00 } //1 \a.exe
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_4 = {75 00 73 00 65 00 72 00 61 00 6e 00 64 00 70 00 63 00 3d 00 } //1 userandpc=
		$a_01_5 = {64 6c 75 72 6c } //1 dlurl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}