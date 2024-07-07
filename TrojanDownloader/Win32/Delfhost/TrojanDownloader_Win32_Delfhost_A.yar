
rule TrojanDownloader_Win32_Delfhost_A{
	meta:
		description = "TrojanDownloader:Win32/Delfhost.A,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3d 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 65 62 42 72 6f 77 73 65 72 31 4e 65 77 57 69 6e 64 6f 77 32 } //10 WebBrowser1NewWindow2
		$a_00_1 = {61 00 62 00 6f 00 75 00 74 00 3a 00 62 00 6c 00 61 00 6e 00 6b 00 } //10 about:blank
		$a_00_2 = {2e 61 73 70 3f 6d 61 63 3d } //10 .asp?mac=
		$a_00_3 = {41 70 70 45 76 65 6e 74 73 5c 53 63 68 65 6d 65 73 5c 41 70 70 73 5c 45 78 70 6c 6f 72 65 72 5c 4e 61 76 69 67 61 74 69 6e 67 5c 2e 43 75 72 72 65 6e 74 } //10 AppEvents\Schemes\Apps\Explorer\Navigating\.Current
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 } //10 Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3
		$a_00_5 = {53 65 72 76 69 63 65 45 78 65 63 75 74 65 } //10 ServiceExecute
		$a_02_6 = {ff ff 84 c0 74 30 90 09 2a 00 50 e8 90 01 03 ff 6a 01 a1 90 01 03 00 50 e8 90 01 03 ff e8 90 01 02 ff ff eb 46 6a 06 a1 90 01 03 00 50 e8 90 01 03 ff e8 90 00 } //1
		$a_02_7 = {ff ff 84 c0 74 30 90 09 25 00 50 e8 90 01 03 ff 6a 01 a1 90 01 03 00 50 e8 90 01 03 ff eb 46 6a 06 a1 90 01 03 00 50 e8 90 01 03 ff e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1) >=61
 
}