
rule TrojanDownloader_Win32_VB_ZA{
	meta:
		description = "TrojanDownloader:Win32/VB.ZA,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3d 00 08 00 00 "
		
	strings :
		$a_00_0 = {37 00 38 00 45 00 31 00 42 00 44 00 44 00 31 00 2d 00 39 00 39 00 34 00 31 00 2d 00 31 00 31 00 63 00 66 00 2d 00 39 00 37 00 35 00 36 00 2d 00 30 00 30 00 41 00 41 00 30 00 30 00 43 00 30 00 30 00 39 00 30 00 38 00 } //10 78E1BDD1-9941-11cf-9756-00AA00C00908
		$a_00_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //10 InternetExplorer.Application
		$a_00_2 = {5b 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 5d 00 } //10 [InternetShortcut]
		$a_00_3 = {4e 00 6f 00 77 00 4d 00 6f 00 6d 00 } //10 NowMom
		$a_01_4 = {63 41 70 70 48 69 64 65 72 } //10 cAppHider
		$a_00_5 = {76 62 36 73 74 6b 69 74 2e 64 6c 6c } //10 vb6stkit.dll
		$a_00_6 = {2f 00 61 00 63 00 74 00 69 00 76 00 65 00 78 00 2f 00 69 00 70 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 3f 00 75 00 5f 00 69 00 70 00 3d 00 } //1 /activex/ipget.php?u_ip=
		$a_00_7 = {70 00 6f 00 70 00 75 00 70 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 75 00 5f 00 73 00 69 00 74 00 65 00 3d 00 } //1 popupall.php?u_site=
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=61
 
}