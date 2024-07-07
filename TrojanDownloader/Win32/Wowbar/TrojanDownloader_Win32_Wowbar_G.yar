
rule TrojanDownloader_Win32_Wowbar_G{
	meta:
		description = "TrojanDownloader:Win32/Wowbar.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 00 00 00 73 76 63 76 65 72 } //2
		$a_01_1 = {2e 63 6f 2e 6b 72 2f 76 65 72 73 69 6f 6e 2f 73 76 63 76 65 72 2e 70 68 70 } //2 .co.kr/version/svcver.php
		$a_01_2 = {2f 75 70 64 61 74 65 2e 77 6f 77 74 6f 6f 6c 62 61 72 2e 63 6f 2e 6b 72 2f } //2 /update.wowtoolbar.co.kr/
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1) >=5
 
}