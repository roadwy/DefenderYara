
rule TrojanDownloader_Win32_Zlob_AMP{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AMP,SIGNATURE_TYPE_PEHSTR_EXT,48 00 47 00 0a 00 00 "
		
	strings :
		$a_00_0 = {6c 69 76 65 2e } //10 live.
		$a_00_1 = {79 61 68 6f 6f 2e } //10 yahoo.
		$a_00_2 = {67 6f 6f 67 6c 65 2e } //10 google.
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //10 Software\Microsoft\Internet Explorer\SearchScopes
		$a_00_4 = {47 65 74 53 79 73 74 65 6d 44 65 66 61 75 6c 74 4c 43 49 44 } //10 GetSystemDefaultLCID
		$a_00_5 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //10 HttpOpenRequestA
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4e 65 74 50 72 6f 6a 65 63 74 } //1 Software\NetProject
		$a_00_7 = {23 37 38 35 75 6a 74 68 67 66 72 77 33 34 36 37 36 75 74 79 6a } //2 #785ujthgfrw34676utyj
		$a_00_8 = {5f 52 45 44 44 5f } //2 _REDD_
		$a_02_9 = {00 00 83 c4 10 85 c0 74 90 01 01 6a 01 68 90 01 04 e8 90 01 02 ff ff 90 02 28 74 90 01 01 6a 02 68 90 01 04 e8 90 01 02 ff ff 90 02 28 74 90 01 01 6a 03 68 90 01 04 e8 90 01 02 ff ff 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*1+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_02_9  & 1)*10) >=71
 
}