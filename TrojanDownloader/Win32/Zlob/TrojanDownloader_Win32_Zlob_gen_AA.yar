
rule TrojanDownloader_Win32_Zlob_gen_AA{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_01_0 = {8d 98 1d c3 14 a3 bb 49 ba 51 7f 57 de e5 ea 34 } //1
		$a_00_1 = {6c 65 6f 73 72 76 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00 } //10
		$a_01_2 = {6c 00 65 00 6f 00 73 00 72 00 76 00 54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //10 leosrvTOOLBAR
		$a_01_3 = {54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 33 00 32 00 } //10 ToolbarWindow32
		$a_00_4 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //10 explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10) >=41
 
}
rule TrojanDownloader_Win32_Zlob_gen_AA_2{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_01_0 = {b5 0d 5c e7 f7 5d f0 4d 97 61 8e fc d1 78 39 12 } //1
		$a_00_1 = {6a 6f 6b 77 6d 70 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00 } //10
		$a_01_2 = {6a 00 6f 00 6b 00 77 00 6d 00 70 00 54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //10 jokwmpTOOLBAR
		$a_01_3 = {54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 33 00 32 00 } //10 ToolbarWindow32
		$a_00_4 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //10 explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10) >=41
 
}
rule TrojanDownloader_Win32_Zlob_gen_AA_3{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 76 87 06 48 f0 d1 43 b3 3b db e6 fe 9a e7 12 } //1
		$a_00_1 = {76 6f 69 70 77 65 74 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00 } //10
		$a_01_2 = {76 00 6f 00 69 00 70 00 77 00 65 00 74 00 54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //10 voipwetTOOLBAR
		$a_01_3 = {54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 33 00 32 00 } //10 ToolbarWindow32
		$a_00_4 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //10 explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10) >=41
 
}
rule TrojanDownloader_Win32_Zlob_gen_AA_4{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,33 00 29 00 06 00 00 "
		
	strings :
		$a_01_0 = {7b 42 30 32 35 33 34 44 37 2d 38 44 39 31 2d 34 39 42 45 2d 41 38 36 34 2d 39 37 44 46 42 38 45 30 42 41 42 34 7d } //1 {B02534D7-8D91-49BE-A864-97DFB8E0BAB4}
		$a_01_1 = {6f 70 74 6e 65 74 2e 54 6f 6f 6c 42 61 72 2e 31 } //10 optnet.ToolBar.1
		$a_00_2 = {6f 70 74 6e 65 74 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00 } //10
		$a_00_3 = {6f 00 70 00 74 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 } //10 optnet.dll
		$a_01_4 = {6f 00 70 00 74 00 6e 00 65 00 74 00 54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //10 optnetTOOLBAR
		$a_00_5 = {77 72 69 74 65 66 69 6c 65 } //10 writefile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10) >=41
 
}
rule TrojanDownloader_Win32_Zlob_gen_AA_5{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,33 00 29 00 0b 00 00 "
		
	strings :
		$a_01_0 = {7b 41 43 39 42 42 44 42 32 2d 38 46 43 44 2d 34 39 43 38 2d 39 36 46 37 2d 43 43 33 43 46 37 42 34 35 33 43 44 7d } //1 {AC9BBDB2-8FCD-49C8-96F7-CC3CF7B453CD}
		$a_01_1 = {7b 36 31 41 42 38 41 33 39 2d 46 43 43 42 2d 34 37 43 43 2d 42 41 46 33 2d 37 35 30 44 31 38 33 34 45 37 37 33 7d } //1 {61AB8A39-FCCB-47CC-BAF3-750D1834E773}
		$a_01_2 = {7b 31 36 39 39 31 33 37 43 2d 42 39 30 45 2d 34 34 38 38 2d 39 37 42 43 2d 35 37 35 43 38 39 36 43 32 42 35 43 7d } //1 {1699137C-B90E-4488-97BC-575C896C2B5C}
		$a_01_3 = {7b 44 46 30 41 43 45 30 43 2d 34 41 33 46 2d 34 41 31 46 2d 38 36 37 36 2d 42 41 31 36 44 45 42 32 33 43 37 30 7d } //1 {DF0ACE0C-4A3F-4A1F-8676-BA16DEB23C70}
		$a_01_4 = {7b 32 31 30 36 42 45 44 45 2d 46 35 45 38 2d 34 44 45 38 2d 41 30 38 31 2d 41 37 45 35 45 41 44 31 35 32 39 42 7d } //1 {2106BEDE-F5E8-4DE8-A081-A7E5EAD1529B}
		$a_01_5 = {7b 37 44 36 31 43 31 42 35 2d 38 36 41 46 2d 34 33 39 46 2d 39 41 43 46 2d 44 31 39 46 44 42 35 46 35 35 43 43 7d } //1 {7D61C1B5-86AF-439F-9ACF-D19FDB5F55CC}
		$a_01_6 = {6e 73 73 66 72 63 68 2e 54 6f 6f 6c 42 61 72 2e 31 } //10 nssfrch.ToolBar.1
		$a_00_7 = {6e 73 73 66 72 63 68 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00 } //10
		$a_00_8 = {6e 00 73 00 73 00 66 00 72 00 63 00 68 00 2e 00 64 00 6c 00 6c 00 } //10 nssfrch.dll
		$a_01_9 = {6e 00 73 00 73 00 66 00 72 00 63 00 68 00 54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //10 nssfrchTOOLBAR
		$a_00_10 = {77 72 69 74 65 66 69 6c 65 } //10 writefile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_01_9  & 1)*10+(#a_00_10  & 1)*10) >=41
 
}